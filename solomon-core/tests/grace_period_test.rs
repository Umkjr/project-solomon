//! Automated Tests for 72-Hour Offline Grace Period Heartbeat & Licensing State Machine.

use solomon_core::heartbeat::{HeartbeatManager, HeartbeatStatus, ACTIVE_WINDOW_SECS, GRACE_WINDOW_SECS, TOTAL_EXPIRY_SECS};
use std::time::{SystemTime, UNIX_EPOCH};

fn current_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn create_valid_test_token() -> [u8; 80] {
    // Generate valid 80-byte encrypted Epoch Token using mock crypto
    let mut token = [0u8; 80];
    let iv = [0x55u8; 32];
    token[0..32].copy_from_slice(&iv);

    // Compute keystream with master key
    let mut decrypt_sponge = solomon_core::crypto::shake::KeccakSponge::new_shake256();
    decrypt_sponge.absorb(b"SOLOMON_KEY_2026_SECURE_LICENSE_");
    decrypt_sponge.absorb(&iv);
    let mut keystream = [0u8; 32];
    decrypt_sponge.squeeze(&mut keystream);

    let desired_salt = [0x77u8; 32];
    let mut ciphertext = [0u8; 32];
    for i in 0..32 {
        ciphertext[i] = desired_salt[i] ^ keystream[i];
    }
    token[32..64].copy_from_slice(&ciphertext);

    // Compute MAC
    let mut mac_sponge = solomon_core::crypto::shake::KeccakSponge::new_shake256();
    mac_sponge.absorb(b"SOLOMON_KEY_2026_SECURE_LICENSE_");
    mac_sponge.absorb(&iv);
    mac_sponge.absorb(&ciphertext);
    let mut mac = [0u8; 16];
    mac_sponge.squeeze(&mut mac);
    token[64..80].copy_from_slice(&mac);

    token
}

#[test]
fn test_heartbeat_lifecycle_state_transitions() {
    let fingerprint = [0x11u8; 32];
    let temp_cache = format!("{}/solomon_test_cache_{}.tmp", std::env::temp_dir().display(), current_ts());
    let mgr = HeartbeatManager::new(fingerprint, Some(temp_cache.clone()));

    // 1. Initial State before any sync: ExpiredFailClosed
    assert_eq!(mgr.get_status(), HeartbeatStatus::ExpiredFailClosed { last_synced: 0, expired_at: 0 });
    assert!(!mgr.is_operational());

    // 2. Successful Sync at timestamp T
    let token = create_valid_test_token();
    let base_time = current_ts();
    let sync_ok = mgr.record_successful_sync(&token, Some(base_time));
    assert!(sync_ok, "Failed to record valid sync");

    // 3. Within 24h: Active status
    let status = mgr.get_status();
    assert!(matches!(status, HeartbeatStatus::Active { last_synced, valid_until } if last_synced == base_time && valid_until == base_time + ACTIVE_WINDOW_SECS));
    assert!(mgr.is_operational());

    // 4. Time travel: 30 hours later (past 24h, within 72h grace)
    mgr.set_last_synced_for_testing(base_time - (30 * 3600));
    let grace_status = mgr.get_status();
    match grace_status {
        HeartbeatStatus::GracePeriod { last_synced, grace_until, remaining_seconds } => {
            assert_eq!(last_synced, base_time - (30 * 3600));
            assert_eq!(grace_until, (base_time - (30 * 3600)) + TOTAL_EXPIRY_SECS);
            assert!(remaining_seconds > 0 && remaining_seconds <= GRACE_WINDOW_SECS);
        }
        _ => panic!("Expected GracePeriod status, got {:?}", grace_status),
    }
    assert!(mgr.is_operational(), "Proxy should remain operational during 72h grace period");

    // 5. Time travel: 100 hours later (past 24h + 72h = 96h total window)
    mgr.set_last_synced_for_testing(base_time - (100 * 3600));
    let expired_status = mgr.get_status();
    assert!(matches!(expired_status, HeartbeatStatus::ExpiredFailClosed { .. }));
    assert!(!mgr.is_operational(), "Proxy must fail-closed after 72-hour grace period expires");

    // Cleanup
    let _ = std::fs::remove_file(temp_cache);
}

#[test]
fn test_heartbeat_cache_recovery_and_tamper_defense() {
    let fingerprint = [0x22u8; 32];
    let temp_cache = format!("{}/solomon_recovery_test_{}.tmp", std::env::temp_dir().display(), current_ts());
    let token = create_valid_test_token();
    let base_time = current_ts();

    // Create and save to cache
    {
        let mgr = HeartbeatManager::new(fingerprint, Some(temp_cache.clone()));
        assert!(mgr.record_successful_sync(&token, Some(base_time)));
    }

    // Reboot / create new manager from the cache file
    {
        let recovered_mgr = HeartbeatManager::new(fingerprint, Some(temp_cache.clone()));
        assert!(recovered_mgr.is_operational(), "Should recover Active state from valid local cache");
    }

    // Tamper with cache file (flip a byte in the token)
    {
        let mut data = std::fs::read(&temp_cache).unwrap();
        data[15] ^= 0xFF; // Flip byte
        std::fs::write(&temp_cache, &data).unwrap();

        // Boot manager with tampered cache
        let tampered_mgr = HeartbeatManager::new(fingerprint, Some(temp_cache.clone()));
        assert_eq!(tampered_mgr.get_status(), HeartbeatStatus::ExpiredFailClosed { last_synced: 0, expired_at: 0 },
            "Tampered cache must be rejected by MAC validation");
        assert!(!tampered_mgr.is_operational());
    }

    // Cleanup
    let _ = std::fs::remove_file(temp_cache);
}
