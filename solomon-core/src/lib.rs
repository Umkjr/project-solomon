#![cfg_attr(not(feature = "std"), no_std)]

pub mod error;
pub mod crypto;

#[cfg(feature = "std")]
pub mod bcd;

#[cfg(feature = "std")]
pub mod ebcdic;

#[cfg(feature = "std")]
pub mod iso8583;

#[cfg(feature = "std")]
pub mod heartbeat;

#[cfg(feature = "std")]
pub mod audit;

#[cfg(feature = "proxy")]
pub mod cbom;

#[cfg(feature = "proxy")]
pub mod proxy;

#[cfg(feature = "proxy")]
pub mod tls_tunnel;

#[cfg(feature = "std")]
pub mod zk;
#[cfg(feature = "proxy")]
pub mod ai;
#[cfg(feature = "proxy")]
pub mod config;
#[cfg(feature = "proxy")]
pub mod hsm;

// Clean Top-Level Public Cryptographic API
pub use crypto::nist_api::{keygen, sign, sign_hedged, verify};
pub use crypto::hybrid::{hybrid_keygen, hybrid_sign, hybrid_verify, HybridPublicKey, HybridSignature, HybridSecretKey};

#[cfg(feature = "proxy")]
pub use solomon_zk::{generate_stark_proof, verify_stark_proof, CompressedStarkProof, StarkVerificationError};