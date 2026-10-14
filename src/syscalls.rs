//! Solana syscalls: names, how many argument registers each takes, and the murmur3 hash sBPF v3
//! programs call them by.
//!
//! Names follow Agave's `syscalls/src/lib.rs` (`create_program_runtime_environment`). Argument
//! counts are for rendering calls only; they do not change the analysis.

/// (name, argument registers, short note)
pub const SYSCALLS: &[(&str, u8, &str)] = &[
    ("abort", 0, "abort the program"),
    ("sol_panic_", 4, "panic with a file, line and column"),
    ("sol_log_", 2, "log a string"),
    ("sol_log_64_", 5, "log five u64 values"),
    ("sol_log_pubkey", 1, "log a public key"),
    ("sol_log_compute_units_", 0, "log remaining compute units"),
    ("sol_log_data", 2, "log data slices (events)"),
    ("sol_create_program_address", 4, "derive a PDA"),
    ("sol_try_find_program_address", 5, "find a PDA and its bump"),
    ("sol_sha256", 3, "SHA-256"),
    ("sol_keccak256", 3, "Keccak-256"),
    ("sol_secp256k1_recover", 4, "secp256k1 public key recovery"),
    ("sol_blake3", 3, "BLAKE3"),
    ("sol_sha512", 3, "SHA-512"),
    ("sol_curve_validate_point", 3, "validate a curve point"),
    ("sol_curve_group_op", 5, "curve group operation"),
    ("sol_curve_multiscalar_mul", 5, "curve multiscalar multiplication"),
    ("sol_curve_decompress", 3, "curve point decompression"),
    ("sol_curve_pairing_map", 4, "curve pairing"),
    ("sol_get_clock_sysvar", 1, "read the Clock sysvar"),
    ("sol_get_epoch_schedule_sysvar", 1, "read the EpochSchedule sysvar"),
    ("sol_get_fees_sysvar", 1, "read the Fees sysvar"),
    ("sol_get_rent_sysvar", 1, "read the Rent sysvar"),
    ("sol_get_last_restart_slot", 1, "read the LastRestartSlot sysvar"),
    ("sol_get_epoch_rewards_sysvar", 1, "read the EpochRewards sysvar"),
    ("sol_get_sysvar", 4, "read part of a sysvar"),
    ("sol_memcpy_", 3, "memcpy"),
    ("sol_memmove_", 3, "memmove"),
    ("sol_memset_", 3, "memset"),
    ("sol_memcmp_", 4, "memcmp"),
    ("sol_get_processed_sibling_instruction", 5, "read a processed sibling instruction"),
    ("sol_get_stack_height", 0, "current CPI stack height"),
    ("sol_set_return_data", 2, "set return data"),
    ("sol_get_return_data", 3, "get return data"),
    ("sol_invoke_signed_c", 5, "cross-program invocation"),
    ("sol_invoke_signed_rust", 5, "cross-program invocation"),
    ("sol_alloc_free_", 2, "heap allocation (deprecated)"),
    ("sol_alt_bn128_group_op", 4, "alt_bn128 group operation"),
    ("sol_alt_bn128_compression", 4, "alt_bn128 compression"),
    ("sol_big_mod_exp", 2, "big modular exponentiation"),
    ("sol_poseidon", 5, "Poseidon hash"),
    ("sol_remaining_compute_units", 0, "remaining compute units"),
    ("sol_get_epoch_stake", 1, "stake of a vote account"),
    ("sol_keccak_p1600", 1, "Keccak-p[1600] permutation"),
];

/// Syscalls after which execution never continues.
pub const NO_RETURN: &[&str] = &["abort", "sol_panic_"];

pub fn info(name: &str) -> Option<(u8, &'static str)> {
    SYSCALLS.iter().find(|(n, _, _)| *n == name).map(|(_, a, d)| (*a, *d))
}

pub fn is_registered(name: &str) -> bool {
    info(name).is_some()
}

/// murmur3 32-bit with seed 0: how sBPF v3 encodes a syscall in `call` (src = 0).
/// Ported from sbpf-inspect (see `interface/mod.rs` for attribution).
pub fn murmur3(data: &[u8]) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h: u32 = 0;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        let mut k = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let rest = chunks.remainder();
    if !rest.is_empty() {
        let mut k: u32 = 0;
        for (i, &byte) in rest.iter().enumerate() {
            k ^= u32::from(byte) << (8 * i);
        }
        h ^= k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

/// The registered syscall whose hash is `hash`.
pub fn by_hash(hash: u32) -> Option<&'static str> {
    SYSCALLS.iter().map(|(n, _, _)| *n).find(|n| murmur3(n.as_bytes()) == hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_match_solana() {
        assert_eq!(murmur3(b"abort"), 0xb6fc_1a11);
        assert_eq!(murmur3(b"sol_log_"), 0x2075_59bd);
        assert_eq!(by_hash(0x2075_59bd), Some("sol_log_"));
    }

    #[test]
    fn no_hash_collisions_in_the_table() {
        let mut seen = std::collections::HashSet::new();
        for (n, _, _) in SYSCALLS {
            assert!(seen.insert(murmur3(n.as_bytes())), "collision for {n}");
        }
    }
}
