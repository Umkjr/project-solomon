// solomon-cloud/src/ai_aggregator.rs

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct GlobalModel {
    pub epoch: u32,
    pub weights: Vec<f32>,
}

/// Applies Byzantine-robust Federated Averaging (FedAvg) using Coordinate-wise Trimmed Mean.
pub fn aggregate_weights_robust(
    current_global: &[f32],
    client_updates: &[Vec<f32>],
) -> Vec<f32> {
    if client_updates.is_empty() {
        return current_global.to_vec();
    }

    let num_params = current_global.len();
    let num_clients = client_updates.len();
    let mut new_global = vec![0.0; num_params];

    // Coordinate-wise trimmed mean to filter out poisoned gradients (Byzantine robustness)
    for i in 0..num_params {
        let mut param_vals: Vec<f32> = client_updates.iter().map(|w| w[i]).collect();
        
        // Sort values to trim outliers
        param_vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        
        // Coordinate-wise trimmed mean (β = 0.20): trims up to 20% extreme Byzantine outliers from each tail
        let trim_count = ((num_clients as f32 * 0.20).ceil() as usize).min((num_clients - 1) / 2);
        
        let valid_vals = if trim_count > 0 && 2 * trim_count < num_clients {
            &param_vals[trim_count..(num_clients - trim_count)]
        } else {
            &param_vals[..]
        };
        
        let sum: f32 = valid_vals.iter().sum();
        let mean = if valid_vals.is_empty() {
            param_vals.iter().sum::<f32>() / num_clients as f32
        } else {
            sum / valid_vals.len() as f32
        };
        
        new_global[i] = mean;
    }

    new_global
}
