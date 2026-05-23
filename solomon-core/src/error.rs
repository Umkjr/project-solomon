//! Error types for ML-DSA-65 implementation
//!
//! This module defines custom error types for the ML-DSA-65 digital signature algorithm.
//! All errors are designed to be non-panic and recoverable where possible.

use core::fmt;

/// Error type for ML-DSA-65 operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaError {
    /// Invalid parameter value provided
    InvalidParameter,
    /// Invalid signature format
    InvalidSignature,
    /// Invalid public key format
    InvalidPublicKey,
    /// Invalid private key format
    InvalidPrivateKey,
    /// Hash function failure
    HashFailure,
    /// Memory allocation failure (for future use)
    MemoryAllocationFailure,
    /// Internal consistency check failed
    InternalError,
}

impl fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlDsaError::InvalidParameter => write!(f, "Invalid parameter value"),
            MlDsaError::InvalidSignature => write!(f, "Invalid signature format"),
            MlDsaError::InvalidPublicKey => write!(f, "Invalid public key format"),
            MlDsaError::InvalidPrivateKey => write!(f, "Invalid private key format"),
            MlDsaError::HashFailure => write!(f, "Hash function failure"),
            MlDsaError::MemoryAllocationFailure => write!(f, "Memory allocation failure"),
            MlDsaError::InternalError => write!(f, "Internal consistency check failed"),
        }
    }
}

impl core::error::Error for MlDsaError {}

/// Result type for ML-DSA-65 operations
pub type Result<T> = core::result::Result<T, MlDsaError>;