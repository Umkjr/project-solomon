//! Safe memory destruction and zeroization utilities.
//!
//! Provides the `Zeroize` trait, `ZeroizeOnDrop` for reference borrowing, and `Zeroized`
//! as an owning wrapper that automatically zeroizes its inner value on Drop.

use crate::crypto::poly::Polynomial;
use crate::crypto::matrix::PolyVector;

/// A trait for types that can be securely scrubbed from memory.
pub trait Zeroize {
    /// Zeroes out the memory of the object using volatile operations.
    fn zeroize(&mut self);
}

/// A scope-bound RAII guard that automatically zeroizes its wrapped reference on Drop.
pub struct ZeroizeOnDrop<'a, T: Zeroize>(pub &'a mut T);

impl<'a, T: Zeroize> Drop for ZeroizeOnDrop<'a, T> {
    #[inline(always)]
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// An owning wrapper that automatically zeroizes its inner value on Drop.
pub struct Zeroized<T: Zeroize> {
    pub value: T,
}

impl<T: Zeroize> Drop for Zeroized<T> {
    #[inline(always)]
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl<T: Zeroize> core::ops::Deref for Zeroized<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: Zeroize> core::ops::DerefMut for Zeroized<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl Zeroize for Polynomial {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe {
            for i in 0..256 {
                core::ptr::write_volatile(&mut self.coeffs[i], 0);
            }
        }
        // Force memory synchronization fence
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl<const N: usize> Zeroize for PolyVector<N> {
    #[inline(always)]
    fn zeroize(&mut self) {
        for i in 0..N {
            self.polys[i].zeroize();
        }
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe {
            for i in 0..N {
                core::ptr::write_volatile(&mut self[i], 0);
            }
        }
        // Force memory synchronization fence
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
