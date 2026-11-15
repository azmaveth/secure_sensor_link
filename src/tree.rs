//! Payload tree: preorder binary decoding and level-order rendering.
//!
//! Decoding is iterative with an explicit stack, so a hostile payload can't
//! exhaust the call stack, and it enforces the node and depth limits while
//! reading, so work stays proportional to the accepted tree. A tree that
//! breaks a limit is then measured in full, so the error reports its real
//! size.

use std::collections::VecDeque;
use std::fmt;

use serde::Serialize;

/// Largest tree accepted, in nodes.
pub const MAX_NODES: usize = 1024;
/// Deepest tree accepted, counting the nodes on the longest root-to-leaf path.
pub const MAX_DEPTH: usize = 64;

const ABSENT: u8 = 0x00;
const PRESENT: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    nodes: Vec<Node>,
    root: Option<usize>,
    depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    value: i32,
    left: Option<usize>,
    right: Option<usize>,
}

/// Size of a tree: its node count, and its depth in nodes on the longest
/// root-to-leaf path. The empty tree is 0 and 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Shape {
    pub nodes: usize,
    pub depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    Truncated {
        offset: usize,
    },
    BadMarker {
        offset: usize,
        byte: u8,
    },
    TrailingBytes {
        count: usize,
    },
    /// Well-formed, but over [`MAX_NODES`] or [`MAX_DEPTH`].
    TooLarge(Shape),
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreeError::Truncated { offset } => write!(f, "tree ends early at byte {offset}"),
            TreeError::BadMarker { offset, byte } => {
                write!(f, "byte {offset} is 0x{byte:02x}, expected a node marker (0x00 or 0x01)")
            }
            TreeError::TrailingBytes { count } => write!(f, "{count} bytes follow the tree"),
            TreeError::TooLarge(Shape { nodes, depth }) => write!(
                f,
                "tree is too large: {nodes} nodes, depth {depth} (limits are {MAX_NODES} nodes, depth {MAX_DEPTH})"
            ),
        }
    }
}

impl std::error::Error for TreeError {}

/// Where a decoded node gets attached.
#[derive(Clone, Copy)]
enum Slot {
    Root,
    Left(usize),
    Right(usize),
}

/// Decodes a payload that must contain exactly one preorder-encoded tree.
pub fn decode(payload: &[u8]) -> Result<Tree, TreeError> {
    let mut nodes: Vec<Node> = Vec::new();
    let mut root = None;
    let mut max_depth = 0;
    // Each entry is a slot still waiting for its encoding, and the depth a
    // node placed there would have. Preorder means left before right, so the
    // right slot is pushed first.
    let mut stack = vec![(Slot::Root, 1usize)];
    let mut pos = 0usize;

    while let Some((slot, depth)) = stack.pop() {
        let (value, next) = read_node(payload, pos)?;
        pos = next;
        let Some(value) = value else { continue };
        if depth > MAX_DEPTH || nodes.len() == MAX_NODES {
            return Err(oversized(payload));
        }

        let index = nodes.len();
        nodes.push(Node { value, left: None, right: None });
        match slot {
            Slot::Root => root = Some(index),
            Slot::Left(parent) => nodes[parent].left = Some(index),
            Slot::Right(parent) => nodes[parent].right = Some(index),
        }
        max_depth = max_depth.max(depth);
        stack.push((Slot::Right(index), depth + 1));
        stack.push((Slot::Left(index), depth + 1));
    }

    expect_end(payload, pos)?;
    Ok(Tree { nodes, root, depth: max_depth })
}

/// The error for a tree that broke a limit: its full size if the rest of the
/// encoding is well-formed, otherwise the encoding error.
fn oversized(payload: &[u8]) -> TreeError {
    match measure(payload) {
        Ok(shape) => TreeError::TooLarge(shape),
        Err(e) => e,
    }
}

/// Scans a whole encoding, ignoring the limits, and returns its size. Only
/// used for trees already known to be too large. Nothing is stored per node,
/// and the stack holds at most depth + 1 entries; the 16-bit payload length
/// caps any tree at 10,922 nodes, so both are bounded.
fn measure(payload: &[u8]) -> Result<Shape, TreeError> {
    let mut shape = Shape::default();
    let mut stack = vec![1usize];
    let mut pos = 0usize;
    while let Some(depth) = stack.pop() {
        let (value, next) = read_node(payload, pos)?;
        pos = next;
        if value.is_some() {
            shape.nodes += 1;
            shape.depth = shape.depth.max(depth);
            stack.push(depth + 1);
            stack.push(depth + 1);
        }
    }
    expect_end(payload, pos)?;
    Ok(shape)
}

/// Reads one node's encoding at `pos`. Returns the node's value (`None` if
/// the node is absent) and the position after it.
fn read_node(payload: &[u8], pos: usize) -> Result<(Option<i32>, usize), TreeError> {
    match payload.get(pos) {
        None => Err(TreeError::Truncated { offset: pos }),
        Some(&ABSENT) => Ok((None, pos + 1)),
        Some(&PRESENT) => {
            let bytes =
                payload.get(pos + 1..pos + 5).ok_or(TreeError::Truncated { offset: payload.len() })?;
            let mut value = [0u8; 4];
            value.copy_from_slice(bytes);
            Ok((Some(i32::from_be_bytes(value)), pos + 5))
        }
        Some(&byte) => Err(TreeError::BadMarker { offset: pos, byte }),
    }
}

/// The payload must hold exactly one tree.
fn expect_end(payload: &[u8], pos: usize) -> Result<(), TreeError> {
    match payload.len() - pos {
        0 => Ok(()),
        count => Err(TreeError::TrailingBytes { count }),
    }
}

impl Tree {
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn shape(&self) -> Shape {
        Shape { nodes: self.nodes.len(), depth: self.depth }
    }

    /// Level order, with `None` for each missing child of a present node and
    /// trailing `None`s removed. The empty tree is `[]`.
    pub fn level_order(&self) -> Vec<Option<i32>> {
        let mut out = Vec::with_capacity(2 * self.nodes.len() + 1);
        let mut queue = VecDeque::with_capacity(self.nodes.len() + 1);
        if let Some(root) = self.root {
            queue.push_back(Some(root));
        }
        while let Some(entry) = queue.pop_front() {
            match entry.and_then(|i| self.nodes.get(i)) {
                Some(node) => {
                    out.push(Some(node.value));
                    queue.push_back(node.left);
                    queue.push_back(node.right);
                }
                None => out.push(None),
            }
        }
        while out.last() == Some(&None) {
            out.pop();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 31-byte example from the spec.
    const SPEC_EXAMPLE: &str =
        concat!("0100000001", "01000000020000", "0100000003", "01000000040000", "01000000050000",);

    fn bytes(hex_text: &str) -> Vec<u8> {
        hex::decode(hex_text).unwrap()
    }

    fn shape(nodes: usize, depth: usize) -> Shape {
        Shape { nodes, depth }
    }

    #[test]
    fn decodes_spec_example() {
        let payload = bytes(SPEC_EXAMPLE);
        assert_eq!(payload.len(), 31);
        let tree = decode(&payload).unwrap();
        assert_eq!(tree.level_order(), vec![Some(1), Some(2), Some(3), None, None, Some(4), Some(5)]);
        assert_eq!(tree.shape(), shape(5, 3));
    }

    #[test]
    fn empty_tree_is_a_single_zero() {
        let tree = decode(&[0]).unwrap();
        assert_eq!(tree.level_order(), Vec::<Option<i32>>::new());
        assert_eq!(tree.shape(), shape(0, 0));
        assert_eq!(decode(&[]).unwrap_err(), TreeError::Truncated { offset: 0 });
    }

    #[test]
    fn negative_values_and_left_spine() {
        // -3 with a left child 7.
        let payload = bytes("01fffffffd01000000070000" /* -3, 7 */);
        let mut payload = payload;
        payload.push(0); // -3's right child
        assert_eq!(decode(&payload).unwrap().level_order(), vec![Some(-3), Some(7)]);
    }

    #[test]
    fn rejects_bad_encodings() {
        assert_eq!(decode(&[2]).unwrap_err(), TreeError::BadMarker { offset: 0, byte: 2 });
        assert_eq!(decode(&[0, 0]).unwrap_err(), TreeError::TrailingBytes { count: 1 });
        assert!(matches!(decode(&[1, 0, 0]).unwrap_err(), TreeError::Truncated { .. }));
        assert!(matches!(decode(&[1, 0, 0, 0, 1, 0]).unwrap_err(), TreeError::Truncated { .. }));
    }

    fn left_spine(depth: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..depth {
            out.push(PRESENT);
            out.extend_from_slice(&(i as i32).to_be_bytes());
        }
        out.extend(std::iter::repeat_n(ABSENT, depth + 1));
        out
    }

    #[test]
    fn depth_limit_is_inclusive() {
        assert_eq!(decode(&left_spine(MAX_DEPTH)).unwrap().shape(), shape(MAX_DEPTH, MAX_DEPTH));
        assert_eq!(decode(&left_spine(MAX_DEPTH + 1)).unwrap_err(), TreeError::TooLarge(shape(65, 65)));
    }

    #[test]
    fn oversized_tree_reports_its_full_size() {
        // Deep enough to overflow a recursive decoder's stack.
        assert_eq!(decode(&left_spine(10_000)).unwrap_err(), TreeError::TooLarge(shape(10_000, 10_000)));
        assert_eq!(
            decode(&left_spine(70)).unwrap_err().to_string(),
            "tree is too large: 70 nodes, depth 70 (limits are 1024 nodes, depth 64)"
        );
    }

    #[test]
    fn oversized_and_malformed_reports_the_malformation() {
        let mut payload = left_spine(MAX_DEPTH + 1);
        payload.push(0);
        assert_eq!(decode(&payload).unwrap_err(), TreeError::TrailingBytes { count: 1 });
        payload.truncate(payload.len() - 3);
        assert!(matches!(decode(&payload).unwrap_err(), TreeError::Truncated { .. }));
    }

    /// A tree of `n` nodes with minimal depth, built in preorder.
    fn balanced(n: usize) -> Vec<u8> {
        fn build(lo: usize, hi: usize, out: &mut Vec<u8>) {
            if lo >= hi {
                out.push(ABSENT);
                return;
            }
            let mid = (lo + hi) / 2;
            out.push(PRESENT);
            out.extend_from_slice(&(mid as i32).to_be_bytes());
            build(lo, mid, out);
            build(mid + 1, hi, out);
        }
        let mut out = Vec::new();
        build(0, n, &mut out);
        out
    }

    #[test]
    fn node_limit_is_inclusive() {
        assert_eq!(decode(&balanced(MAX_NODES)).unwrap().shape(), shape(MAX_NODES, 11));
        assert_eq!(decode(&balanced(MAX_NODES + 1)).unwrap_err(), TreeError::TooLarge(shape(1025, 11)));
    }
}
