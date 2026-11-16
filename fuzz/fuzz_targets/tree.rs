//! Arbitrary bytes as a payload. Decoding must not panic; a tree it accepts
//! must be within the limits and must encode back to exactly the input, and
//! one it rejects as too large must really be over a limit.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_sensor_link::tree::{self, MAX_DEPTH, MAX_NODES, TreeError};

/// Rebuilds the preorder encoding from the level-order rendering, without
/// using the decoder.
fn encode(level_order: &[Option<i32>]) -> Vec<u8> {
    struct Node {
        value: i32,
        left: Option<usize>,
        right: Option<usize>,
    }
    let mut nodes: Vec<Node> = Vec::new();
    let mut entries = level_order.iter().copied();
    let new_node = |nodes: &mut Vec<Node>, value: i32| {
        nodes.push(Node { value, left: None, right: None });
        nodes.len() - 1
    };
    let root = entries.next().flatten().map(|value| new_node(&mut nodes, value));
    // Present nodes in level order; each takes the next two entries as its
    // children, and entries past the end are absent.
    let mut next_parent = 0;
    while next_parent < nodes.len() {
        let left = entries.next().flatten().map(|value| new_node(&mut nodes, value));
        let right = entries.next().flatten().map(|value| new_node(&mut nodes, value));
        nodes[next_parent].left = left;
        nodes[next_parent].right = right;
        next_parent += 1;
    }
    assert!(entries.next().is_none(), "level order has entries with no parent");

    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(slot) = stack.pop() {
        match slot {
            None => out.push(0),
            Some(index) => {
                out.push(1);
                out.extend_from_slice(&nodes[index].value.to_be_bytes());
                stack.push(nodes[index].right);
                stack.push(nodes[index].left);
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    match tree::decode(data) {
        Ok(tree) => {
            let shape = tree.shape();
            assert!(shape.nodes <= MAX_NODES && shape.depth <= MAX_DEPTH);
            assert_eq!(shape.nodes, tree.len());
            let level_order = tree.level_order();
            assert!(level_order.len() <= 2 * shape.nodes + 1);
            assert_ne!(level_order.last(), Some(&None), "trailing nulls are removed");
            assert_eq!(level_order.iter().flatten().count(), shape.nodes);
            assert_eq!(encode(&level_order), data, "the encoding is canonical");
        }
        Err(TreeError::TooLarge(shape)) => {
            assert!(shape.nodes > MAX_NODES || shape.depth > MAX_DEPTH);
            assert!(shape.depth <= shape.nodes);
        }
        Err(_) => {}
    }
});
