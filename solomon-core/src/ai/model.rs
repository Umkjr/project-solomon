// solomon-core/src/ai/model.rs

use crate::ai::linalg::{Matrix, Vector};
use rand::Rng;

/// Applies ReLU activation in-place.
fn relu(vec: &mut Vector) {
    for val in vec.data.iter_mut() {
        if *val < 0.0 {
            *val = 0.0;
        }
    }
}

/// Applies Derivative of ReLU for backprop.
fn relu_deriv(output: &Vector, grad: &mut Vector) {
    for (out, g) in output.data.iter().zip(grad.data.iter_mut()) {
        if *out <= 0.0 {
            *g = 0.0;
        }
    }
}

/// Samples a normal random variable N(0, std_dev^2) using Box-Muller transform.
pub fn sample_gaussian(std_dev: f32, rng: &mut impl Rng) -> f32 {
    let u1: f32 = rng.gen_range(1e-7..1.0);
    let u2: f32 = rng.gen_range(0.0..1.0);
    let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f32::consts::PI * u2).cos();
    z0 * std_dev
}

pub struct EdgeAutoencoder {
    pub w1: Matrix, // 4x8
    pub b1: Vector, // 4
    pub w2: Matrix, // 8x4
    pub b2: Vector, // 8
    
    // Gradients for local batch
    grad_w1: Matrix,
    grad_b1: Vector,
    grad_w2: Matrix,
    grad_b2: Vector,

    // Empirical metrics for Federated Sync
    pub accumulated_loss: f32,
    pub sample_count: usize,
}

impl EdgeAutoencoder {
    pub fn new(rng: &mut impl Rng) -> Self {
        Self {
            w1: Matrix::xavier_init(4, 8, rng),
            b1: Vector::new(4),
            w2: Matrix::xavier_init(8, 4, rng),
            b2: Vector::new(8),
            grad_w1: Matrix::new(4, 8),
            grad_b1: Vector::new(4),
            grad_w2: Matrix::new(8, 4),
            grad_b2: Vector::new(8),
            accumulated_loss: 0.0,
            sample_count: 0,
        }
    }

    /// Records empirical sample loss during training.
    pub fn record_loss(&mut self, loss: f32) {
        self.accumulated_loss += loss;
        self.sample_count += 1;
    }

    /// Returns average empirical loss across recent samples and resets tracking counters.
    pub fn get_avg_loss_and_reset(&mut self) -> f32 {
        if self.sample_count == 0 {
            return 0.01; // Baseline nominal reconstruction loss
        }
        let avg = self.accumulated_loss / self.sample_count as f32;
        self.accumulated_loss = 0.0;
        self.sample_count = 0;
        avg
    }

    /// Forward pass returning reconstruction and hidden layer state
    pub fn forward(&self, x: &Vector) -> (Vector, Vector) {
        let mut h = self.w1.vector_mul(x);
        h.add(&self.b1);
        relu(&mut h);

        let mut x_hat = self.w2.vector_mul(&h);
        x_hat.add(&self.b2);
        // Linear output layer for autoencoder

        (x_hat, h)
    }

    /// Computes Anomaly Score S(x) based on MSE loss.
    pub fn compute_anomaly_score(&self, x: &Vector) -> (f32, f32) {
        let (x_hat, _) = self.forward(x);
        let mut error = x.clone();
        for (e, x_h) in error.data.iter_mut().zip(x_hat.data.iter()) {
            *e -= x_h;
        }
        
        let mse = error.dot(&error) / 8.0;
        // Normalize to [0, 1] assuming baseline MSE threshold is around 0.1
        let score = (mse / 0.1).min(1.0);
        (score, mse)
    }

    /// Backpropagation for a single sample, accumulating gradients.
    pub fn backward(&mut self, x: &Vector, x_hat: &Vector, h: &Vector) {
        // Output layer error: 2 * (x_hat - x) / N
        let mut d_x_hat = Vector::new(8);
        for i in 0..8 {
            d_x_hat.data[i] = 2.0 * (x_hat.data[i] - x.data[i]) / 8.0;
        }

        // Accumulate b2 gradients
        self.grad_b2.add(&d_x_hat);

        // Accumulate w2 gradients: d_x_hat * h^T
        for i in 0..8 {
            for j in 0..4 {
                self.grad_w2.data[i * 4 + j] += d_x_hat.data[i] * h.data[j];
            }
        }

        // Hidden layer error: W2^T * d_x_hat
        let mut d_h = Vector::new(4);
        for j in 0..4 {
            for i in 0..8 {
                d_h.data[j] += self.w2.data[i * 4 + j] * d_x_hat.data[i];
            }
        }
        relu_deriv(h, &mut d_h);

        // Accumulate b1 gradients
        self.grad_b1.add(&d_h);

        // Accumulate w1 gradients: d_h * x^T
        for i in 0..4 {
            for j in 0..8 {
                self.grad_w1.data[i * 8 + j] += d_h.data[i] * x.data[j];
            }
        }
    }

    /// Applies Differential Privacy (Gaussian noise via Box-Muller) to accumulated gradients and resets them.
    /// Returns the noise-injected flat weight vector for Federated Sync.
    pub fn apply_dp_and_get_weights(&mut self, rng: &mut impl Rng) -> Vec<f32> {
        let learning_rate = 0.01;
        let clip_norm = 1.0;
        let noise_std = 0.05;

        // Clip and apply W1
        let norm_w1: f32 = self.grad_w1.data.iter().map(|x| x*x).sum::<f32>().sqrt();
        let scale_w1 = if norm_w1 > clip_norm { clip_norm / norm_w1 } else { 1.0 };
        for i in 0..self.w1.data.len() {
            let noise = sample_gaussian(noise_std, rng);
            self.w1.data[i] -= learning_rate * (self.grad_w1.data[i] * scale_w1 + noise);
            self.grad_w1.data[i] = 0.0;
        }

        // Clip and apply B1
        for i in 0..self.b1.data.len() {
            let noise = sample_gaussian(noise_std, rng);
            self.b1.data[i] -= learning_rate * (self.grad_b1.data[i] + noise);
            self.grad_b1.data[i] = 0.0;
        }

        // Clip and apply W2
        let norm_w2: f32 = self.grad_w2.data.iter().map(|x| x*x).sum::<f32>().sqrt();
        let scale_w2 = if norm_w2 > clip_norm { clip_norm / norm_w2 } else { 1.0 };
        for i in 0..self.w2.data.len() {
            let noise = sample_gaussian(noise_std, rng);
            self.w2.data[i] -= learning_rate * (self.grad_w2.data[i] * scale_w2 + noise);
            self.grad_w2.data[i] = 0.0;
        }

        // Clip and apply B2
        for i in 0..self.b2.data.len() {
            let noise = sample_gaussian(noise_std, rng);
            self.b2.data[i] -= learning_rate * (self.grad_b2.data[i] + noise);
            self.grad_b2.data[i] = 0.0;
        }

        // Flatten all weights for sync
        let mut flat_weights = Vec::new();
        flat_weights.extend_from_slice(&self.w1.data);
        flat_weights.extend_from_slice(&self.b1.data);
        flat_weights.extend_from_slice(&self.w2.data);
        flat_weights.extend_from_slice(&self.b2.data);

        flat_weights
    }
}
