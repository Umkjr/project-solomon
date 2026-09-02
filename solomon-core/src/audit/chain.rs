use crate::audit::record::AuditRecord;
use crate::audit::crypto_traits::AuditHasher;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum AuditChainError {
    #[error("Genesis block has invalid previous hash (expected all zeros): index {0}")]
    InvalidGenesisPrevious(usize),
    
    #[error("Hash chain broken at index {index}: expected previous_hash '{expected}', found '{found}'")]
    BrokenPreviousHash { index: usize, expected: String, found: String },
    
    #[error("Record hash mismatch at index {index}: content was tampered with or recomputed hash '{expected}' does not match recorded '{found}'")]
    RecordHashMismatch { index: usize, expected: String, found: String },
}

pub struct AuditChain;

impl AuditChain {
    pub const GENESIS_HASH: &'static str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// Verifies the cryptographic hash chain integrity for a slice of audit records.
    /// Pinpoints exact index and failure mode for any tampering, deletion, or reordering.
    pub fn verify_chain(
        records: &[AuditRecord],
        hasher: &dyn AuditHasher,
    ) -> Result<(), AuditChainError> {
        Self::verify_chain_with_initial_hash(records, hasher, Self::GENESIS_HASH)
    }

    /// Verifies the cryptographic hash chain integrity for a slice of audit records,
    /// allowing specification of the expected previous_hash for the first record
    /// (essential for verifying daily rotated log segments continuing from previous days).
    pub fn verify_chain_with_initial_hash(
        records: &[AuditRecord],
        hasher: &dyn AuditHasher,
        expected_initial_hash: &str,
    ) -> Result<(), AuditChainError> {
        if records.is_empty() {
            return Ok(());
        }

        // 1. Verify initial record previous_hash
        if records[0].previous_hash != expected_initial_hash {
            return Err(AuditChainError::InvalidGenesisPrevious(0));
        }

        let expected_genesis_hash = AuditRecord::compute_hash(
            hasher,
            records[0].timestamp_utc,
            &records[0].event_id,
            &records[0].route_target,
            &records[0].crypto_profile,
            &records[0].localization_region,
            &records[0].system_action,
            &records[0].previous_hash,
        );

        if records[0].current_hash != expected_genesis_hash {
            return Err(AuditChainError::RecordHashMismatch {
                index: 0,
                expected: expected_genesis_hash,
                found: records[0].current_hash.clone(),
            });
        }

        // 2. Verify subsequent links
        for i in 1..records.len() {
            let prev = &records[i - 1];
            let curr = &records[i];

            // Verify previous_hash linkage
            if curr.previous_hash != prev.current_hash {
                return Err(AuditChainError::BrokenPreviousHash {
                    index: i,
                    expected: prev.current_hash.clone(),
                    found: curr.previous_hash.clone(),
                });
            }

            // Verify current record content integrity
            let expected_current_hash = AuditRecord::compute_hash(
                hasher,
                curr.timestamp_utc,
                &curr.event_id,
                &curr.route_target,
                &curr.crypto_profile,
                &curr.localization_region,
                &curr.system_action,
                &curr.previous_hash,
            );

            if curr.current_hash != expected_current_hash {
                return Err(AuditChainError::RecordHashMismatch {
                    index: i,
                    expected: expected_current_hash,
                    found: curr.current_hash.clone(),
                });
            }
        }

        Ok(())
    }
}

