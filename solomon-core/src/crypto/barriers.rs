//! Hardware-level speculative execution barriers to protect against out-of-order cache timing attacks.

/// Inserts a hardware serialization instruction to block speculative execution.
///
/// Under x86/x86_64, this emits the `lfence` instruction.
/// Under aarch64 (ARM64), this emits the `isb sy` instruction.
/// On other platforms, it evaluates as a compiler fence/no-op.
#[inline(always)]
pub fn speculative_barrier() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        unsafe {
            core::arch::asm!("lfence", options(nostack, preserves_flags));
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            core::arch::asm!("isb sy", options(nostack, preserves_flags));
        }
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
