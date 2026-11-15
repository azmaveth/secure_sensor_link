//! Payload tree: preorder binary decoding and level-order rendering.
//!
//! Decoding is iterative with an explicit stack, so a hostile payload can't
//! exhaust the call stack, and it enforces the node and depth limits while
//! reading, so work stays proportional to the accepted tree.

use std::collections::VecDeque;
use std::fmt;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    value: i32,
    left: Option<usize>,
    right: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    Truncated { offset: usize },
    BadMarker { offset: usize, byte: u8 },
    TooManyNodes,
    TooDeep,
    TrailingBytes { count: usize },
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreeError::Truncated { offset } => write!(f, "tree ends early at byte {offset}"),
            TreeError::BadMarker { offset, byte } => {
                write!(f, "byte {offset} is 0x{byte:02x}, expected a node marker (0x00 or 0x01)")
            }
            TreeError::TooManyNodes => write!(f, "tree has more than {MAX_NODES} nodes"),
            TreeError::TooDeep => write!(f, "tree is deeper than {MAX_DEPTH} levels"),
            TreeError::TrailingBytes { count } => write!(f, "{count} bytes follow the tree"),
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
    // Each entry is a slot still waiting for its encoding, and the depth a
    // node placed there would have. Preorder means left before right, so the
    // right slot is pushed first.
    let mut stack = vec![(Slot::Root, 1usize)];
    let mut pos = 0usize;

    while let Some((slot, depth)) = stack.pop() {
        let marker = *payload.get(pos).ok_or(TreeError::Truncated { offset: pos })?;
        match marker {
            ABSENT => pos += 1,
            PRESENT => {
                if depth > MAX_DEPTH {
                    return Err(TreeError::TooDeep);
                }
                if nodes.len() == MAX_NODES {
                    return Err(TreeError::TooManyNodes);
                }
                let bytes =
                    payload.get(pos + 1..pos + 5).ok_or(TreeError::Truncated { offset: payload.len() })?;
                let mut value = [0u8; 4];
                value.copy_from_slice(bytes);
                pos += 5;

                let index = nodes.len();
                nodes.push(Node { value: i32::from_be_bytes(value), left: None, right: None });
                match slot {
                    Slot::Root => root = Some(index),
                    Slot::Left(parent) => nodes[parent].left = Some(index),
                    Slot::Right(parent) => nodes[parent].right = Some(index),
                }
                stack.push((Slot::Right(index), depth + 1));
                stack.push((Slot::Left(index), depth + 1));
            }
            byte => return Err(TreeError::BadMarker { offset: pos, byte }),
        }
    }

    if pos != payload.len() {
        return Err(TreeError::TrailingBytes { count: payload.len() - pos });
    }
    Ok(Tree { nodes, root })
}

impl Tree {
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
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

    #[test]
    fn decodes_spec_example() {
        let payload = bytes(SPEC_EXAMPLE);
        assert_eq!(payload.len(), 31);
        let tree = decode(&payload).unwrap();
        assert_eq!(tree.level_order(), vec![Some(1), Some(2), Some(3), None, None, Some(4), Some(5)]);
    }

    #[test]
    fn empty_tree_is_a_single_zero() {
        assert_eq!(decode(&[0]).unwrap().level_order(), Vec::<Option<i32>>::new());
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
        assert_eq!(decode(&left_spine(MAX_DEPTH)).unwrap().len(), MAX_DEPTH);
        assert_eq!(decode(&left_spine(MAX_DEPTH + 1)).unwrap_err(), TreeError::TooDeep);
        // Deep enough to overflow a recursive decoder's stack.
        assert_eq!(decode(&left_spine(10_000)).unwrap_err(), TreeError::TooDeep);
    }

    /// A complete-ish tree of `n` nodes built in preorder (shallow).
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
        assert_eq!(decode(&balanced(MAX_NODES)).unwrap().len(), MAX_NODES);
        assert_eq!(decode(&balanced(MAX_NODES + 1)).unwrap_err(), TreeError::TooManyNodes);
    }
}
