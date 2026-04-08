//! Maze Generator for SDP Maze
//!
//! Generates a maze topology for privacy transfers:
//! - Multiple splits and merges
//! - Parameterized with encrypted seed
//! - Deterministic but unpredictable to observers

use solana_sdk::signature::{Keypair, Signer};
use serde::{Deserialize, Serialize};


use crate::config::{MazeParameters, MergeStrategy, TX_FEE_LAMPORTS};
use crate::core::utils::{seeded_random, fibonacci, add_noise};
use crate::error::{MazeError, Result};

/// A node in the maze graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MazeNode {
    /// Unique index of this node
    pub index: u16,
    /// Level/depth in the maze (0 = deposit, max = final)
    pub level: u8,
    /// Solana address (pubkey)
    pub address: String,
    /// Encrypted keypair bytes
    pub keypair_encrypted: Vec<u8>,
    /// Incoming edges (node indices that send to this node)
    pub inputs: Vec<u16>,
    /// Outgoing edges (node indices this node sends to)
    pub outputs: Vec<u16>,
    /// Amount to receive (in lamports)
    pub amount_in: u64,
    /// Amount to send out (after TX fee)
    pub amount_out: u64,
    /// Transaction signature for incoming TX
    pub tx_in_signature: Option<String>,
    /// Transaction signatures for outgoing TXs
    pub tx_out_signatures: Vec<Option<String>>,
    /// Status: pending, completed, failed
    pub status: String,
}

/// The complete maze graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MazeGraph {
    /// All nodes in the maze
    pub nodes: Vec<MazeNode>,
    /// Maze parameters (encrypted for receiver only)
    pub parameters: MazeParameters,
    /// Total levels in maze
    pub total_levels: u8,
    /// Deposit node index (always 0)
    pub deposit_index: u16,
    /// Final node index (sends to stealth address)
    pub final_index: u16,
    /// Total TX count
    pub total_transactions: u16,
}

/// Maze Generator
pub struct MazeGenerator {
    params: MazeParameters,
}

impl MazeGenerator {
    pub fn new(params: MazeParameters) -> Self {
        Self { params }
    }

    pub fn with_random_params() -> Self {
        Self {
            params: MazeParameters::random(),
        }
    }

    /// Generate a maze graph for a transfer
    /// 
    /// # Arguments
    /// * `total_amount` - Total amount to transfer (in lamports)
    /// * `encrypt_fn` - Function to encrypt keypair bytes
    /// 
    /// # Returns
    /// * `MazeGraph` - The generated maze structure
    pub fn generate<F>(&self, total_amount: u64, encrypt_fn: F) -> Result<MazeGraph>
    where
        F: Fn(&[u8]) -> Result<Vec<u8>>,
    {
        let mut nodes: Vec<MazeNode> = Vec::new();
        let mut node_index: u16 = 0;

        // Calculate total TX fees needed
        let estimated_txs = self.estimate_transaction_count();
        let total_fees = TX_FEE_LAMPORTS * estimated_txs as u64;
        
        if total_amount <= total_fees {
            return Err(MazeError::InsufficientFunds {
                required: total_fees + 1,
                available: total_amount,
            });
        }

        let net_amount = total_amount - total_fees;

        // Level 0: Deposit node
        let deposit_keypair = Keypair::new();
        let deposit_node = MazeNode {
            index: node_index,
            level: 0,
            address: deposit_keypair.pubkey().to_string(),
            keypair_encrypted: encrypt_fn(&deposit_keypair.to_bytes())?,
            inputs: vec![],
            outputs: vec![], // Will be filled later
            amount_in: total_amount,
            amount_out: 0, // Will be calculated
            tx_in_signature: None,
            tx_out_signatures: vec![],
            status: "pending".to_string(),
        };
        nodes.push(deposit_node);
        node_index += 1;

        // Generate intermediate levels
        let num_levels = self.params.hop_count;
        let mut current_level_nodes: Vec<u16> = vec![0]; // Start with deposit node
        let mut current_level_amounts: Vec<u64> = vec![net_amount];

        for level in 1..num_levels {
            let (new_nodes, new_amounts) = self.generate_level(
                level,
                &current_level_nodes,
                &current_level_amounts,
                &mut node_index,
                &encrypt_fn,
                &mut nodes,
            )?;
            current_level_nodes = new_nodes;
            current_level_amounts = new_amounts;
        }

        // Final level: Merge all to single node
        let final_keypair = Keypair::new();
        let final_amount: u64 = current_level_amounts.iter().sum();
        let final_node = MazeNode {
            index: node_index,
            level: num_levels,
            address: final_keypair.pubkey().to_string(),
            keypair_encrypted: encrypt_fn(&final_keypair.to_bytes())?,
            inputs: current_level_nodes.clone(),
            outputs: vec![], // Final node sends to stealth address
            amount_in: final_amount,
            amount_out: final_amount.saturating_sub(TX_FEE_LAMPORTS),
            tx_in_signature: None,
            tx_out_signatures: vec![],
            status: "pending".to_string(),
        };
        
        let final_index = node_index;
        nodes.push(final_node);

        // Update outputs for previous level nodes
        for &prev_idx in &current_level_nodes {
            if let Some(node) = nodes.get_mut(prev_idx as usize) {
                node.outputs.push(final_index);
            }
        }

        // Calculate amount_out for all nodes
        self.calculate_amounts(&mut nodes)?;

        // Count total transactions
        let total_transactions = self.count_transactions(&nodes);

        Ok(MazeGraph {
            nodes,
            parameters: self.params.clone(),
            total_levels: num_levels + 1,
            deposit_index: 0,
            final_index,
            total_transactions,
        })
    }

    /// Generate nodes for a single level
    fn generate_level<F>(
        &self,
        level: u8,
        prev_nodes: &[u16],
        prev_amounts: &[u64],
        node_index: &mut u16,
        encrypt_fn: &F,
        nodes: &mut Vec<MazeNode>,
    ) -> Result<(Vec<u16>, Vec<u64>)>
    where
        F: Fn(&[u8]) -> Result<Vec<u8>>,
    {
        let mut new_node_indices: Vec<u16> = Vec::new();
        let mut new_amounts: Vec<u64> = Vec::new();

        // Determine split/merge behavior based on strategy and level
        let should_split = self.should_split_at_level(level);
        let should_merge = self.should_merge_at_level(level);

        if should_split && prev_nodes.len() < 4 {
            // Split: Each node splits into 2-3 nodes
            for (i, (&prev_idx, &amount)) in prev_nodes.iter().zip(prev_amounts.iter()).enumerate() {
                let split_count = self.get_split_count(level, i as u64);
                let split_amounts = self.split_amount(amount, split_count);

                for (j, split_amount) in split_amounts.into_iter().enumerate() {
                    let keypair = Keypair::new();
                    let noised_amount = add_noise(
                        split_amount,
                        self.params.amount_noise,
                        &self.params.seed,
                        (*node_index as u64) * 1000 + j as u64,
                    );

                    let node = MazeNode {
                        index: *node_index,
                        level,
                        address: keypair.pubkey().to_string(),
                        keypair_encrypted: encrypt_fn(&keypair.to_bytes())?,
                        inputs: vec![prev_idx],
                        outputs: vec![],
                        amount_in: noised_amount,
                        amount_out: 0,
                        tx_in_signature: None,
                        tx_out_signatures: vec![],
                        status: "pending".to_string(),
                    };

                    // Update previous node's outputs
                    if let Some(prev_node) = nodes.get_mut(prev_idx as usize) {
                        prev_node.outputs.push(*node_index);
                    }

                    new_node_indices.push(*node_index);
                    new_amounts.push(noised_amount);
                    nodes.push(node);
                    *node_index += 1;
                }
            }
        } else if should_merge && prev_nodes.len() > 2 {
            // Merge: Combine multiple nodes into fewer
            let merge_groups = self.create_merge_groups(prev_nodes, prev_amounts);
            
            for (inputs, amounts) in merge_groups {
                let keypair = Keypair::new();
                let total: u64 = amounts.iter().sum();

                let node = MazeNode {
                    index: *node_index,
                    level,
                    address: keypair.pubkey().to_string(),
                    keypair_encrypted: encrypt_fn(&keypair.to_bytes())?,
                    inputs: inputs.clone(),
                    outputs: vec![],
                    amount_in: total,
                    amount_out: 0,
                    tx_in_signature: None,
                    tx_out_signatures: vec![],
                    status: "pending".to_string(),
                };

                // Update previous nodes' outputs
                for &prev_idx in &inputs {
                    if let Some(prev_node) = nodes.get_mut(prev_idx as usize) {
                        prev_node.outputs.push(*node_index);
                    }
                }

                new_node_indices.push(*node_index);
                new_amounts.push(total);
                nodes.push(node);
                *node_index += 1;
            }
        } else {
            // Pass through: 1-to-1 mapping
            for (&prev_idx, &amount) in prev_nodes.iter().zip(prev_amounts.iter()) {
                let keypair = Keypair::new();
                let noised_amount = add_noise(
                    amount,
                    self.params.amount_noise,
                    &self.params.seed,
                    *node_index as u64,
                );

                let node = MazeNode {
                    index: *node_index,
                    level,
                    address: keypair.pubkey().to_string(),
                    keypair_encrypted: encrypt_fn(&keypair.to_bytes())?,
                    inputs: vec![prev_idx],
                    outputs: vec![],
                    amount_in: noised_amount,
                    amount_out: 0,
                    tx_in_signature: None,
                    tx_out_signatures: vec![],
                    status: "pending".to_string(),
                };

                if let Some(prev_node) = nodes.get_mut(prev_idx as usize) {
                    prev_node.outputs.push(*node_index);
                }

                new_node_indices.push(*node_index);
                new_amounts.push(noised_amount);
                nodes.push(node);
                *node_index += 1;
            }
        }

        Ok((new_node_indices, new_amounts))
    }

    /// Determine if we should split at this level
    fn should_split_at_level(&self, level: u8) -> bool {
        let ratio = level as f64 / self.params.hop_count as f64;
        
        match self.params.merge_strategy {
            MergeStrategy::Early => ratio > 0.5,  // Split in second half
            MergeStrategy::Late => ratio < 0.5,   // Split in first half
            MergeStrategy::Middle => ratio < 0.3 || ratio > 0.7,
            MergeStrategy::Fibonacci => {
                let fib_idx = (level + self.params.fib_offset) % 20;
                fibonacci(fib_idx) % 2 == 0
            }
            MergeStrategy::Random => {
                seeded_random(&self.params.seed, level as u64) % 2 == 0
            }
        }
    }

    /// Determine if we should merge at this level
    fn should_merge_at_level(&self, level: u8) -> bool {
        let ratio = level as f64 / self.params.hop_count as f64;
        
        match self.params.merge_strategy {
            MergeStrategy::Early => ratio < 0.5,  // Merge in first half
            MergeStrategy::Late => ratio > 0.5,   // Merge in second half
            MergeStrategy::Middle => ratio > 0.3 && ratio < 0.7,
            MergeStrategy::Fibonacci => {
                let fib_idx = (level + self.params.fib_offset) % 20;
                fibonacci(fib_idx) % 2 == 1
            }
            MergeStrategy::Random => {
                seeded_random(&self.params.seed, level as u64 + 1000) % 2 == 0
            }
        }
    }

    /// Get number of splits for a node
    fn get_split_count(&self, level: u8, node_idx: u64) -> usize {
        let rand_val = seeded_random(&self.params.seed, level as u64 * 100 + node_idx);
        let base = 2 + (rand_val % 2) as usize; // 2 or 3
        base.min(4) // Max 4 splits
    }

    /// Split amount into parts
    fn split_amount(&self, amount: u64, parts: usize) -> Vec<u64> {
        if parts <= 1 {
            return vec![amount];
        }

        let mut amounts = Vec::with_capacity(parts);
        let mut remaining = amount;

        for i in 0..(parts - 1) {
            // Use golden ratio for interesting splits
            let ratio = self.params.split_ratio + (i as f64 * 0.1);
            let part = (remaining as f64 / ratio) as u64;
            let part = part.max(TX_FEE_LAMPORTS * 2); // Minimum viable amount
            amounts.push(part);
            remaining = remaining.saturating_sub(part);
        }

        // Last part gets the rest
        amounts.push(remaining);
        amounts
    }

    /// Create merge groups from previous nodes
    fn create_merge_groups(&self, prev_nodes: &[u16], prev_amounts: &[u64]) -> Vec<(Vec<u16>, Vec<u64>)> {
        let mut groups: Vec<(Vec<u16>, Vec<u64>)> = Vec::new();
        
        // Simple strategy: merge pairs
        let mut i = 0;
        while i < prev_nodes.len() {
            if i + 1 < prev_nodes.len() {
                groups.push((
                    vec![prev_nodes[i], prev_nodes[i + 1]],
                    vec![prev_amounts[i], prev_amounts[i + 1]],
                ));
                i += 2;
            } else {
                groups.push((
                    vec![prev_nodes[i]],
                    vec![prev_amounts[i]],
                ));
                i += 1;
            }
        }
        
        groups
    }

    /// Calculate amount_out for all nodes
    fn calculate_amounts(&self, nodes: &mut Vec<MazeNode>) -> Result<()> {
        for i in 0..nodes.len() {
            let output_count = nodes[i].outputs.len();
            if output_count > 0 {
                // Reserve TX fee for each output
                let total_fees = TX_FEE_LAMPORTS * output_count as u64;
                let amount_in = nodes[i].amount_in;
                nodes[i].amount_out = amount_in.saturating_sub(total_fees);
            }
        }
        Ok(())
    }

    /// Count total transactions in the maze
    fn count_transactions(&self, nodes: &[MazeNode]) -> u16 {
        nodes.iter()
            .map(|n| n.outputs.len() as u16)
            .sum::<u16>()
            + 1 // +1 for final transfer to stealth
    }

    /// Estimate transaction count before generation
    fn estimate_transaction_count(&self) -> u16 {
        // Rough estimate based on hop count and average branching
        let avg_branch = (self.params.split_ratio * 1.5) as u16;
        (self.params.hop_count as u16 * avg_branch).max(10)
    }
}

impl MazeGraph {
    /// Get execution order (topological sort by level)
    pub fn get_execution_order(&self) -> Vec<&MazeNode> {
        let mut ordered: Vec<&MazeNode> = self.nodes.iter().collect();
        ordered.sort_by_key(|n| n.level);
        ordered
    }

    /// Get nodes at a specific level
    pub fn get_nodes_at_level(&self, level: u8) -> Vec<&MazeNode> {
        self.nodes.iter().filter(|n| n.level == level).collect()
    }

    /// Get deposit node
    pub fn get_deposit_node(&self) -> Option<&MazeNode> {
        self.nodes.get(self.deposit_index as usize)
    }

    /// Get final node
    pub fn get_final_node(&self) -> Option<&MazeNode> {
        self.nodes.get(self.final_index as usize)
    }

    /// Check if all nodes are completed
    pub fn is_completed(&self) -> bool {
        self.nodes.iter().all(|n| n.status == "completed")
    }

    /// Get progress (completed nodes / total nodes)
    pub fn get_progress(&self) -> (usize, usize) {
        let completed = self.nodes.iter().filter(|n| n.status == "completed").count();
        (completed, self.nodes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_encrypt(data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    #[test]
    fn test_maze_generation() {
        let params = MazeParameters::default();
        let generator = MazeGenerator::new(params);
        
        let amount = 1_000_000_000; // 1 SOL
        let maze = generator.generate(amount, dummy_encrypt).unwrap();

        assert!(maze.nodes.len() >= 2);
        assert_eq!(maze.deposit_index, 0);
        assert!(maze.final_index > 0);
        assert!(maze.total_transactions > 0);
    }

    #[test]
    fn test_maze_topology() {
        let mut params = MazeParameters::default();
        params.hop_count = 5;
        let generator = MazeGenerator::new(params);
        
        let amount = 5_000_000_000; // 5 SOL
        let maze = generator.generate(amount, dummy_encrypt).unwrap();

        // Check deposit node
        let deposit = maze.get_deposit_node().unwrap();
        assert_eq!(deposit.level, 0);
        assert!(deposit.inputs.is_empty());

        // Check final node
        let final_node = maze.get_final_node().unwrap();
        assert!(final_node.outputs.is_empty());
    }

    #[test]
    fn test_execution_order() {
        let params = MazeParameters::default();
        let generator = MazeGenerator::new(params);
        
        let maze = generator.generate(1_000_000_000, dummy_encrypt).unwrap();
        let order = maze.get_execution_order();

        // Should be sorted by level
        let mut prev_level = 0;
        for node in order {
            assert!(node.level >= prev_level);
            prev_level = node.level;
        }
    }
}
