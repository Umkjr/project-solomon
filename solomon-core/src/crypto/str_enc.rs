//! Compile-time string encryption and runtime transient decryption.
//!
//! Provides the `EncryptedString` structure and the `enc_str!` macro to perform compile-time
//! XOR obfuscation of sensitive string literals (URLs, diagnostic tags, error messages),
//! decrypting them in-memory only when needed and zeroizing the transient stack allocation
//! immediately after.

/// Encrypted string container housing compile-time ciphertext.
#[derive(Clone, Copy)]
pub struct EncryptedString<const N: usize> {
    pub ciphertext: [u8; N],
    pub key: u8,
}

impl<const N: usize> EncryptedString<N> {
    /// Compiles and XOR-encrypts plaintext bytes at compile time.
    pub const fn new(plaintext: &[u8], key: u8) -> Self {
        let mut ciphertext = [0u8; N];
        let mut i = 0;
        // Simple and robust const-friendly loop
        while i < N {
            if i < plaintext.len() {
                ciphertext[i] = plaintext[i] ^ key;
            } else {
                ciphertext[i] = key;
            }
            i += 1;
        }
        Self { ciphertext, key }
    }

    /// Decrypts the ciphertext into a short-lived stack buffer.
    ///
    /// The caller is responsible for zeroizing or dropping the returned array immediately
    /// after use to prevent persistent memory retention.
    #[inline(always)]
    pub fn decrypt(&self) -> [u8; N] {
        let mut plaintext = [0u8; N];
        unsafe {
            for i in 0..N {
                core::ptr::write_volatile(&mut plaintext[i], self.ciphertext[i] ^ self.key);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        plaintext
    }
}

/// Helper macro to declare compile-time encrypted strings.
#[macro_export]
macro_rules! enc_str {
    ($string:expr, $key:expr) => {{
        const STR: &[u8] = $string.as_bytes();
        const LEN: usize = STR.len();
        const ENC: $crate::crypto::str_enc::EncryptedString<LEN> =
            $crate::crypto::str_enc::EncryptedString::new(STR, $key);
        ENC
    }};
}
