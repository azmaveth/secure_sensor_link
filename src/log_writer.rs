//! A log stream that never makes its writer wait.
//!
//! Writing diagnostics straight to stderr can block: if stderr is a pipe
//! that nobody reads, a write waits once the pipe is full, and the receiver
//! would stop answering commands. [`BackgroundLog`] hands each line to a
//! thread through a bounded queue instead. When the queue is full the line
//! is dropped and counted, and the count is reported in an `events_dropped`
//! line once there is room again. The receiver's own thread never waits on
//! the log, and the queue's size bounds the memory it can hold.

use std::io::{self, Write};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use crate::event::Event;

/// Lines the queue holds before new ones are dropped. A line is a few
/// hundred bytes, so this is well under a megabyte.
pub const DEFAULT_QUEUE_LINES: usize = 1024;

/// Longest line accepted. Events are far shorter; anything longer is
/// dropped rather than buffered.
const MAX_LINE_LEN: usize = 16 * 1024;

pub struct BackgroundLog {
    /// `None` once finished, or if the writer thread could not be started;
    /// every line is then dropped.
    sender: Option<SyncSender<Vec<u8>>>,
    /// Signalled by the writer thread when it has written everything.
    done: Receiver<()>,
    /// Bytes of the line being assembled, up to its newline.
    line: Vec<u8>,
    /// The current line outgrew [`MAX_LINE_LEN`]; skip to its newline.
    skipping: bool,
    /// Lines dropped since the last `events_dropped` line was queued.
    dropped: u64,
}

impl BackgroundLog {
    /// Starts a thread that writes queued lines to `sink`, flushing after
    /// each, and ignores write errors. If the thread can't be started, the
    /// log drops everything; the receiver carries on either way.
    pub fn spawn<W: Write + Send + 'static>(mut sink: W, queue_lines: usize) -> Self {
        let (sender, lines) = sync_channel::<Vec<u8>>(queue_lines);
        let (finished, done) = sync_channel::<()>(1);
        let writer = thread::Builder::new().name("log-writer".into()).spawn(move || {
            for line in lines {
                let _ = sink.write_all(&line);
                let _ = sink.flush();
            }
            let _ = finished.send(());
        });
        BackgroundLog {
            sender: writer.is_ok().then_some(sender),
            done,
            line: Vec::new(),
            skipping: false,
            dropped: 0,
        }
    }

    /// Lines dropped and not yet reported.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Stops taking lines and waits up to `grace` for the queued ones to be
    /// written. If the sink is still blocked after that, they are abandoned:
    /// shutting down must not hang on the log either.
    pub fn finish(mut self, grace: Duration) {
        let deadline = Instant::now() + grace;
        // The last `events_dropped` line needs room in the queue; give the
        // writer thread until the deadline to make some.
        while !self.report_dropped() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        // Closing the queue lets the writer thread run out of lines and stop.
        self.sender = None;
        let _ = self.done.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    }

    /// Queues one complete line, or drops it if there is no room.
    fn submit(&mut self, line: Vec<u8>) {
        if !self.report_dropped() || !self.try_send(line) {
            self.dropped += 1;
        }
    }

    /// Queues the `events_dropped` line if any are owed. Returns whether
    /// nothing is owed any more.
    fn report_dropped(&mut self) -> bool {
        if self.dropped == 0 {
            return true;
        }
        let mut notice = Event::EventsDropped { count: self.dropped }.to_json().into_bytes();
        notice.push(b'\n');
        let sent = self.try_send(notice);
        if sent {
            self.dropped = 0;
        }
        sent
    }

    fn try_send(&self, line: Vec<u8>) -> bool {
        self.sender.as_ref().is_some_and(|sender| sender.try_send(line).is_ok())
    }
}

impl Write for BackgroundLog {
    /// Never blocks and never fails: bytes are gathered into lines, and each
    /// complete line is queued or dropped.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for chunk in bytes.split_inclusive(|&b| b == b'\n') {
            let ends_line = chunk.last() == Some(&b'\n');
            if !self.skipping {
                if self.line.len() + chunk.len() > MAX_LINE_LEN {
                    self.line = Vec::new();
                    self.skipping = true;
                    self.dropped += 1;
                } else {
                    self.line.extend_from_slice(chunk);
                }
            }
            if ends_line {
                if !self.skipping {
                    let line = std::mem::take(&mut self.line);
                    self.submit(line);
                }
                self.skipping = false;
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

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

        /// Waits until the writer thread has taken `n` lines off the queue.
        fn wait_for_writes_started(&self, n: usize) {
            while self.started.load(Ordering::SeqCst) < n {
                thread::yield_now();
            }
        }

        fn wait_for_lines(&self, n: usize) {
            while self.lines().len() < n {
                thread::yield_now();
            }
        }
    }

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.started.fetch_add(1, Ordering::SeqCst);
            let _open = self.gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            self.written.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Shuts the sink and gets the writer thread stuck in it holding
    /// "line 0", so that the queue's contents are known from then on.
    fn block<'a>(sink: &'a Sink, log: &mut BackgroundLog) -> std::sync::MutexGuard<'a, ()> {
        let blocked = sink.gate.lock().unwrap();
        writeln!(log, "line 0").unwrap();
        sink.wait_for_writes_started(1);
        blocked
    }

    #[test]
    fn lines_are_written_in_order() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 8);
        for i in 0..5 {
            writeln!(log, "line {i}").unwrap();
        }
        log.finish(GRACE);
        assert_eq!(sink.lines(), ["line 0", "line 1", "line 2", "line 3", "line 4"]);
    }

    #[test]
    fn a_line_may_arrive_in_pieces() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 8);
        log.write_all(b"one").unwrap();
        log.write_all(b"\ntwo\nthr").unwrap();
        log.write_all(b"ee\n").unwrap();
        log.write_all(b"unfinished").unwrap();
        log.finish(GRACE);
        assert_eq!(sink.lines(), ["one", "two", "three"], "a line with no newline is never written");
    }

    #[test]
    fn a_blocked_sink_drops_lines_instead_of_blocking_the_writer() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 4);
        let blocked = block(&sink, &mut log);
        // Far more lines than the queue holds. Every write returns at once;
        // if any waited for the sink, the test would hang here.
        for i in 1..1000 {
            writeln!(log, "line {i}").unwrap();
        }
        assert_eq!(log.dropped(), 995, "the queue kept lines 1 to 4");

        drop(blocked);
        log.finish(GRACE);
        assert_eq!(
            sink.lines(),
            ["line 0", "line 1", "line 2", "line 3", "line 4", r#"{"event":"events_dropped","count":995}"#]
        );
    }

    #[test]
    fn dropped_lines_are_reported_before_the_next_line_that_fits() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 4);
        let blocked = block(&sink, &mut log);
        for i in 1..50 {
            writeln!(log, "line {i}").unwrap();
        }
        assert_eq!(log.dropped(), 45);
        drop(blocked);
        // Once the five kept lines are written the queue is empty again.
        sink.wait_for_lines(5);
        writeln!(log, "late").unwrap();
        assert_eq!(log.dropped(), 0, "reported");
        log.finish(GRACE);
        assert_eq!(sink.lines()[5..], [r#"{"event":"events_dropped","count":45}"#, "late"]);
    }

    #[test]
    fn an_overlong_line_is_dropped_and_the_next_one_kept() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 8);
        log.write_all(&vec![b'x'; MAX_LINE_LEN + 1]).unwrap();
        log.write_all(b"still the long line\nnext\n").unwrap();
        log.finish(GRACE);
        assert_eq!(sink.lines(), [r#"{"event":"events_dropped","count":1}"#, "next"]);
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
        for i in 0..10 {
            writeln!(log, "line {i}").unwrap();
        }
        log.finish(GRACE);
    }

    #[test]
    fn finishing_does_not_wait_for_ever_on_a_blocked_sink() {
        let sink = Sink::default();
        let mut log = BackgroundLog::spawn(sink.clone(), 4);
        let _blocked = block(&sink, &mut log);
        for i in 1..10 {
            writeln!(log, "line {i}").unwrap();
        }
        let started = Instant::now();
        log.finish(Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
