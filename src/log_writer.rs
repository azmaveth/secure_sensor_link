//! Where diagnostic events go, and a log that never makes the receiver wait.
//!
//! Writing diagnostics straight to stderr can block: if stderr is a pipe
//! that nobody reads, a write waits once the pipe is full, and the receiver
//! would stop answering commands. [`BackgroundLog`] queues each event for a
//! writer thread instead. The receiver's own thread never waits on the log,
//! and the queues' sizes bound the memory they can hold.
//!
//! There are two queues. Security events ([`Event::is_security`]) have one
//! to themselves, and the writer thread takes from it first. Those events
//! are few by construction: per camera, at most 256 `key_revoked` and two
//! `final_key_id` for the life of the store, and one `timestamp_beyond_i64`
//! per boot. That is under 520 lines for both cameras, so a queue of
//! [`DEFAULT_QUEUE_LINES`] holds everything one boot can produce, and no
//! amount of other events can push a security event out. Only many restarts
//! while the log stays blocked could fill it.
//!
//! When a queue is full the event is dropped and counted. The writer thread
//! reports the counts in an `events_dropped` line as soon as the log accepts
//! a line again; the report takes no queue space, so it can't be dropped.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use crate::event::Event;

/// Lines each queue holds before new ones are dropped. A line is a few
/// hundred bytes, so both queues together stay well under a megabyte.
pub const DEFAULT_QUEUE_LINES: usize = 1024;

/// Somewhere diagnostic events can be sent. Sending must not fail: a log
/// that can't take an event deals with that itself.
pub trait EventSink {
    fn emit(&mut self, event: &Event);
}

impl<S: EventSink + ?Sized> EventSink for &mut S {
    fn emit(&mut self, event: &Event) {
        (**self).emit(event);
    }
}

/// Writes each event to `W` as a JSON line, at once, on the caller's thread.
/// Write errors are ignored. Right for a buffer or a file; for a stream that
/// can block, use [`BackgroundLog`].
pub struct LineSink<W>(pub W);

impl<W: Write> EventSink for LineSink<W> {
    fn emit(&mut self, event: &Event) {
        let _ = writeln!(self.0, "{}", event.to_json());
        let _ = self.0.flush();
    }
}

/// Events dropped and not yet reported, by class.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Dropped {
    pub security: u64,
    pub other: u64,
}

#[derive(Default)]
struct Queues {
    security: VecDeque<Vec<u8>>,
    other: VecDeque<Vec<u8>>,
    dropped: Dropped,
    /// No more events are coming; the writer stops once the queues are empty.
    closed: bool,
}

#[derive(Default)]
struct Shared {
    queues: Mutex<Queues>,
    /// Signalled when there is something for the writer thread to do.
    ready: Condvar,
}

impl Shared {
    /// The lock is only ever held for a push or a pop, so a poisoned lock
    /// still guards consistent queues.
    fn lock(&self) -> MutexGuard<'_, Queues> {
        self.queues.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What the writer thread does next.
enum Next {
    Line(Vec<u8>),
    Report(Dropped),
    Stop,
}

pub struct BackgroundLog {
    shared: Arc<Shared>,
    capacity: usize,
    /// Signalled by the writer thread when it has written everything.
    done: Receiver<()>,
    /// False if the writer thread could not be started; events are then
    /// discarded.
    running: bool,
}

impl BackgroundLog {
    /// Starts a thread that writes queued events to `sink` as JSON lines,
    /// flushing after each and ignoring write errors. Each of the two queues
    /// holds `queue_lines` lines. If the thread can't be started, the log
    /// discards everything; the receiver carries on either way.
    pub fn spawn<W: Write + Send + 'static>(mut sink: W, queue_lines: usize) -> Self {
        let shared = Arc::new(Shared::default());
        let (finished, done) = sync_channel::<()>(1);
        let for_writer = Arc::clone(&shared);
        let writer = thread::Builder::new().name("log-writer".into()).spawn(move || {
            loop {
                let line = match next(&for_writer) {
                    Next::Line(line) => line,
                    Next::Report(dropped) => {
                        line_for(&Event::EventsDropped { security: dropped.security, other: dropped.other })
                    }
                    Next::Stop => break,
                };
                let _ = sink.write_all(&line);
                let _ = sink.flush();
            }
            let _ = finished.send(());
        });
        BackgroundLog { shared, capacity: queue_lines, done, running: writer.is_ok() }
    }

    /// Events dropped and not yet reported.
    pub fn dropped(&self) -> Dropped {
        self.shared.lock().dropped
    }

    /// Stops taking events and waits up to `grace` for the queued ones to be
    /// written. If the sink is still blocked after that, they are abandoned:
    /// shutting down must not hang on the log either.
    pub fn finish(self, grace: Duration) {
        self.shared.lock().closed = true;
        self.shared.ready.notify_one();
        if self.running {
            let _ = self.done.recv_timeout(grace);
        }
    }
}

impl EventSink for BackgroundLog {
    /// Queues the event, or counts it as dropped if its queue is full. Never
    /// waits for the sink.
    fn emit(&mut self, event: &Event) {
        if !self.running {
            return;
        }
        let line = line_for(event);
        {
            let mut guard = self.shared.lock();
            // Borrow the fields through one plain reference, so two of them
            // can be borrowed at once.
            let queues = &mut *guard;
            let (queue, dropped) = if event.is_security() {
                (&mut queues.security, &mut queues.dropped.security)
            } else {
                (&mut queues.other, &mut queues.dropped.other)
            };
            if queue.len() < self.capacity {
                queue.push_back(line);
            } else {
                *dropped += 1;
            }
        }
        self.shared.ready.notify_one();
    }
}

fn line_for(event: &Event) -> Vec<u8> {
    let mut line = event.to_json().into_bytes();
    line.push(b'\n');
    line
}

/// Waits for the writer thread's next job. A report of dropped events comes
/// first: the thread only gets here once the sink has taken the previous
/// line, so this is the earliest moment the report can be written. Then
/// security events, then the rest.
fn next(shared: &Shared) -> Next {
    let mut queues = shared.lock();
    loop {
        if queues.dropped != Dropped::default() {
            return Next::Report(std::mem::take(&mut queues.dropped));
        }
        if let Some(line) = queues.security.pop_front().or_else(|| queues.other.pop_front()) {
            return Next::Line(line);
        }
        if queues.closed {
            return Next::Stop;
        }
        queues = shared.ready.wait(queues).unwrap_or_else(PoisonError::into_inner);
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use super::*;

    const GRACE: Duration = Duration::from_secs(5);

    /// A sink the test can read afterwards, and can hold shut to imitate a
    /// pipe that nobody is reading.
    #[derive(Clone, Default)]
    struct Sink {
        written: Arc<Mutex<Vec<u8>>>,
        gate: Arc<Mutex<()>>,
        /// Writes started, including one waiting at the gate.
        started: Arc<AtomicUsize>,
    }

    impl Sink {
        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.written.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(String::from)
                .collect()
        }
    }

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.started.fetch_add(1, Ordering::SeqCst);
            let _open = self.gate.lock().unwrap_or_else(PoisonError::into_inner);
            self.written.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// An ordinary event, told apart by `seq`.
    fn other(seq: u32) -> Event {
        Event::TreeSizeRecord {
            camera: "cam1",
            key_id: 0,
            seq,
            nodes: 1,
            depth: 1,
            max_nodes_seen: 1,
            max_depth_seen: 1,
        }
    }

    /// A security event, told apart by `key_id`.
    fn security(key_id: u8) -> Event {
        Event::KeyRevoked {
            camera: "cam1",
            key_id,
            discarded: 0,
            replay_bar: None,
            set_timeline: false,
            retired_keys: Vec::new(),
        }
    }

    fn json(event: &Event) -> String {
        event.to_json()
    }

    fn dropped(security: u64, other: u64) -> String {
        json(&Event::EventsDropped { security, other })
    }

    /// Shuts the sink and gets the writer thread stuck in it holding
    /// `other(0)`, so that the queues' contents are known from then on.
    fn block<'a>(sink: &'a Sink, log: &mut BackgroundLog) -> MutexGuard<'a, ()> {
        let blocked = sink.gate.lock().unwrap();
        log.emit(&other(0));
        while sink.started.load(Ordering::SeqCst) < 1 {
            thread::yield_now();
        }
        blocked
    }

    #[test]
    fn events_are_written_in_order() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 8);
        for seq in 0..5 {
            log.emit(&other(seq));
        }
        log.finish(GRACE);
        assert_eq!(sink.lines(), (0..5).map(|seq| json(&other(seq))).collect::<Vec<_>>());
    }

    #[test]
    fn security_events_are_written_ahead_of_the_rest() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 8);
        let blocked = block(&sink, &mut log);
        log.emit(&other(1));
        log.emit(&other(2));
        log.emit(&security(7));
        log.emit(&other(3));
        log.emit(&security(8));
        drop(blocked);
        log.finish(GRACE);
        let expected = [other(0), security(7), security(8), other(1), other(2), other(3)];
        assert_eq!(sink.lines(), expected.iter().map(json).collect::<Vec<_>>());
    }

    #[test]
    fn a_blocked_sink_drops_events_instead_of_blocking_the_receiver() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 4);
        let blocked = block(&sink, &mut log);
        // Far more events than the queue holds. Every call returns at once;
        // if any waited for the sink, the test would hang here.
        for seq in 1..1000 {
            log.emit(&other(seq));
        }
        assert_eq!(log.dropped(), Dropped { security: 0, other: 995 }, "the queue kept 1 to 4");

        drop(blocked);
        log.finish(GRACE);
        // The report is written as soon as the sink takes a line again.
        let mut expected = vec![json(&other(0)), dropped(0, 995)];
        expected.extend((1..=4).map(|seq| json(&other(seq))));
        assert_eq!(sink.lines(), expected);
    }

    #[test]
    fn a_flood_of_other_events_cannot_push_out_a_security_event() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 16);
        let blocked = block(&sink, &mut log);
        for seq in 1..=5000 {
            log.emit(&other(seq));
            if seq % 500 == 0 {
                log.emit(&security((seq / 500) as u8));
            }
        }
        assert_eq!(log.dropped(), Dropped { security: 0, other: 5000 - 16 });
        drop(blocked);
        log.finish(GRACE);
        let lines = sink.lines();
        for key_id in 1..=10 {
            assert!(lines.contains(&json(&security(key_id))), "key_revoked {key_id} was lost");
        }
        assert!(lines.contains(&dropped(0, 5000 - 16)));
    }

    #[test]
    fn dropped_security_events_are_counted_separately() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 2);
        let blocked = block(&sink, &mut log);
        for key_id in 0..5 {
            log.emit(&security(key_id));
        }
        log.emit(&other(1));
        assert_eq!(log.dropped(), Dropped { security: 3, other: 0 });
        drop(blocked);
        log.finish(GRACE);
        assert_eq!(
            sink.lines(),
            [json(&other(0)), dropped(3, 0), json(&security(0)), json(&security(1)), json(&other(1))]
        );
    }

    #[test]
    fn a_later_drop_gets_its_own_report() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 1);
        let blocked = block(&sink, &mut log);
        log.emit(&other(1));
        log.emit(&other(2));
        drop(blocked);
        while sink.lines().len() < 3 {
            thread::yield_now();
        }
        assert_eq!(log.dropped(), Dropped::default(), "reported");
        log.emit(&other(3));
        log.finish(GRACE);
        assert_eq!(sink.lines(), [json(&other(0)), dropped(0, 1), json(&other(1)), json(&other(3))]);
    }

    #[test]
    fn line_sink_writes_json_lines_and_ignores_errors() {
        let mut buffer = Vec::new();
        LineSink(&mut buffer).emit(&security(1));
        assert_eq!(String::from_utf8(buffer).unwrap(), format!("{}\n", json(&security(1))));
        LineSink(Broken).emit(&security(1));
    }

    /// A sink that always fails, like a closed stderr.
    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn a_failing_sink_is_ignored() {
        let mut log = BackgroundLog::spawn(Broken, 2);
        for seq in 0..10 {
            log.emit(&other(seq));
        }
        log.finish(GRACE);
    }

    #[test]
    fn finishing_does_not_wait_for_ever_on_a_blocked_sink() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 4);
        let _blocked = block(&sink, &mut log);
        for seq in 1..10 {
            log.emit(&other(seq));
        }
        let started = Instant::now();
        log.finish(Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
