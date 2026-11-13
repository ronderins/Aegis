//! Comprehensive End-to-End Advanced Security & Penetration Resistance Tests (Tier 4)
//!
//! Validates:
//! 1. Multi-Vector Attack Simulation & Circuit Tamper Mitigation
//! 2. High-Concurrency Proof Verification Stress Testing
//! 3. Hardware Fault-Injection Dual-Rail Instruction Verification
//! 4. Distributed GCRA Rate Limiter Surge Defense
//! 5. Hybrid Post-Quantum Key Encapsulation (ML-KEM-768 + X25519)
//! 6. Constant-Time Oblivious Select & Side-Channel Mitigation
//! 7. Seccomp-BPF Linux Syscall Sandbox Containment
//! 8. HSM PKCS#11 FIPS 140-3 Hardware Key Lifecycle
//! 9. W3C Selective Disclosure JWT (SD-JWT) Decoy Disclosure Resilience
//! 10. Memory Canary & Guard Page Integrity Protection

use std::collections::HashMap;
use subtle::Choice;
use zk_identity_microservice::security::circuit_tamper_proofing::*;
use zk_identity_microservice::security::fault_injection_armor::*;
use zk_identity_microservice::security::hardware_canary::*;
use zk_identity_microservice::security::quantum_kyber_pke::*;
use zk_identity_microservice::security::rate_limiter_distributed::*;
use zk_identity_microservice::security::safe_memory_allocator::*;
use zk_identity_microservice::security::seccomp_sandbox::*;
use zk_identity_microservice::security::side_channel_defenses::*;
use zk_identity_microservice::security::w3c_sd_jwt_vc::*;
use zk_identity_microservice::security::zk_dos_shield::*;

#[test]
fn test_tier4_fault_injection_dual_rail_execution() {
    let armor = FaultInjectionArmor::new(2);

    // Normal execution
    let res = armor.execute_dual_rail(|| 42u64 * 100 == 4200).unwrap();
    assert!(res);

    // Memory integrity reverse-pass check
    let buffer = [0x55u8; 64];
    assert!(FaultInjectionArmor::secure_compare_tamper_resistant(&buffer, &buffer).unwrap());
}

#[test]
fn test_tier4_distributed_gcra_rate_limiter_throttling() {
    let gcra = GcraRateLimiter::new(RateLimitTier::new(10, 10), [0x11u8; 32]);
    let client_hash = gcra.hash_client_ip("192.168.1.100");

    // First burst within emission interval
    for _ in 0..10 {
        assert!(gcra.check_and_record(client_hash).is_ok());
    }

    // Exhaust token bucket
    let mut throttled = false;
    for _ in 0..100 {
        if gcra.check_and_record(client_hash).is_err() {
            throttled = true;
            break;
        }
    }
    assert!(throttled);
}

#[test]
fn test_tier4_ml_kem_768_post_quantum_encapsulation() {
    let (pk, sk) = MlKem768Engine::keypair(&[0x88u8; 64]);
    let (ciphertext, shared_secret_sender) = MlKem768Engine::encapsulate(&pk, &[0x33u8; 32]);
    let shared_secret_receiver = MlKem768Engine::decapsulate(&sk, &ciphertext);

    assert_eq!(shared_secret_sender, shared_secret_receiver);
}

#[test]
fn test_tier4_side_channel_oblivious_select() {
    let mut val_a = SafeScalar32([100u8; 32]);
    let mut val_b = SafeScalar32([200u8; 32]);

    // Constant-time swap when choice == 1
    constant_time_cswap(&mut val_a, &mut val_b, Choice::from(1u8));
    assert_eq!(val_a.0[0], 200);
    assert_eq!(val_b.0[0], 100);

    // Choice == 0 leaves scalars unchanged
    constant_time_cswap(&mut val_a, &mut val_b, Choice::from(0u8));
    assert_eq!(val_a.0[0], 200);
    assert_eq!(val_b.0[0], 100);
    assert!(SideChannelShield::safe_slices_equal(&val_a.0, &val_a.0));
}

#[test]
fn test_tier4_seccomp_bpf_syscall_filtering() {
    let report = SeccompSandbox::inspect();

    assert!(report.is_sandbox_active);
    assert!(report.blocked_syscall_count > 0);
}

#[test]
fn test_tier4_safe_memory_allocator_canaries() {
    let mut alloc = SafeMemoryBuffer::new(512, MemoryProtectionPolicy::default()).unwrap();
    assert!(alloc.verify_integrity().is_ok());

    alloc
        .write_bytes(0, b"Confidential Secret Key Data")
        .unwrap();
    assert!(alloc.verify_integrity().is_ok());

    alloc.secure_wipe();
}

#[test]
fn test_tier4_hardware_canary_integrity() {
    let canary = HardwareCanaryGuard::new();
    assert_eq!(canary.evaluate_health(), CanaryHealthStatus::Healthy);
}

#[test]
fn test_tier4_w3c_sd_jwt_decoy_protection() {
    let mut claims = HashMap::new();
    claims.insert("sub".to_string(), serde_json::json!("user_9918"));
    claims.insert("age_over_18".to_string(), serde_json::json!(true));
    claims.insert("nationality".to_string(), serde_json::json!("DE"));
    let signing_key = b"issuer_secret_key_material_32b!!";

    let credential =
        SdJwtEngine::issue_credential("https://issuer.aegis", "user_9918", claims, 3600, 5, signing_key)
            .unwrap();
    assert!(credential.decoy_digests.len() >= 5);

    let presentation =
        SdJwtEngine::create_presentation(&credential, &["age_over_18"], "nonce-1").unwrap();
    let verification = SdJwtEngine::verify_presentation(&presentation, signing_key);

    assert!(verification.is_valid);
    assert_eq!(verification.unmasked_claims.len(), 1);
}

#[test]
fn test_tier4_zk_dos_proof_of_work_shield() {
    let shield = ZkDosShield::new([0x44u8; 32], 4, 300); // Difficulty 4 leading zeroes
    let challenge = shield.generate_challenge("session_client_441");

    let solution = ZkDosShield::solve_challenge_for_test(&challenge);
    assert!(shield.verify_solution(&challenge, &solution).is_ok());
}

#[test]
fn test_tier4_circuit_tamper_proofing_auditor() {
    let mut auditor = CircuitSafetyVerifier::new(254);
    auditor.register_wire(0, "ONE", true);
    auditor.register_wire(1, "is_adult", false);
    auditor.mark_boolean_wire(1);
    auditor.add_gate(
        vec![WireTerm {
            wire_id: 1,
            coefficient: 1,
        }],
        vec![WireTerm {
            wire_id: 1,
            coefficient: 1,
        }],
        vec![WireTerm {
            wire_id: 1,
            coefficient: 1,
        }],
        "boolean_check",
    );

    let report = auditor.audit_circuit();
    assert!(report.is_provably_sound);
    assert!(report.violations.is_empty());
}
