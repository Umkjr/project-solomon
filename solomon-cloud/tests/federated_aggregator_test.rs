use solomon_control_plane::ai_aggregator::aggregate_weights_robust;

#[test]
fn test_robust_fedavg_byzantine_rejection() {
    let current_global = vec![0.5; 5];
    
    // Simulate 10 honest clients and 2 Byzantine clients
    let mut client_updates = Vec::new();
    
    for _ in 0..10 {
        client_updates.push(vec![0.51, 0.49, 0.50, 0.52, 0.48]);
    }
    
    // Byzantine Poisoned gradients (extreme values)
    client_updates.push(vec![10.0, -10.0, 10.0, -10.0, 10.0]);
    client_updates.push(vec![10.0, -10.0, 10.0, -10.0, 10.0]);
    
    let new_global = aggregate_weights_robust(&current_global, &client_updates);
    
    // The robust aggregator should trim the Byzantine outliers and average the honest ones
    for val in new_global {
        assert!(val > 0.45 && val < 0.55, "Poisoned weights bypass robust aggregator! val={}", val);
    }
}
