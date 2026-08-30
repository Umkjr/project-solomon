#![cfg(feature = "proxy")]
use solomon_core::ai::model::EdgeAutoencoder;
use solomon_core::ai::feature::extract_features;

#[test]
fn test_federated_ai_forward_backward_dp() {
    let mut rng = rand::thread_rng();
    let mut model = EdgeAutoencoder::new(&mut rng);

    // Extract mock features
    let features = extract_features(b"MOCK_ISO_PAYLOAD", 1700000000);
    assert_eq!(features.data.len(), 8);

    // Forward pass
    let (x_hat, h) = model.forward(&features);
    assert_eq!(x_hat.data.len(), 8);
    assert_eq!(h.data.len(), 4);

    // Initial anomaly score
    let (score1, mse1) = model.compute_anomaly_score(&features);
    assert!(score1 >= 0.0 && score1 <= 1.0);
    assert!(mse1 >= 0.0);

    // Record sample loss
    model.record_loss(mse1);
    assert_eq!(model.sample_count, 1);

    // Backward pass
    model.backward(&features, &x_hat, &h);

    // Apply Differential Privacy and get weights
    let dp_weights = model.apply_dp_and_get_weights(&mut rng);
    
    // Total parameters = w1 (32) + b1 (4) + w2 (32) + b2 (8) = 76
    assert_eq!(dp_weights.len(), 76);

    let avg_loss = model.get_avg_loss_and_reset();
    assert_eq!(avg_loss, mse1);
    assert_eq!(model.sample_count, 0);

    // Second forward pass should execute cleanly
    let (score2, _) = model.compute_anomaly_score(&features);
    assert!(score2 >= 0.0 && score2 <= 1.0);
}
