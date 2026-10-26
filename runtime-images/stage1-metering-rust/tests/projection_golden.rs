use agentguard_stage1_metering_gateway::config::Scope;
use agentguard_stage1_metering_gateway::projection::parse_rehearsal;
use serde_json::Value;

const GOLDEN: &[u8] = include_bytes!("fixtures/rehearsal-projection.json");
const DIGEST: &str = "sha256:de1db6e2dd7152bc911b60ee6a278340a3ddf9b30e4e5cc1ae12d833a4f0bbfd";

fn scope() -> Scope {
    Scope {
        authorization_digest:
            "sha256:98b3e1f9de98a34cf62e64dace1dc7c2e0d1c31e01bffcb027d262bafe83292a".into(),
        plan_digest: format!("sha256:{}", "1".repeat(64)),
        profile_digest: format!("sha256:{}", "2".repeat(64)),
        pricing_digest: agentguard_stage1_metering_gateway::PRICING_DIGEST.into(),
        redaction_digest: format!("sha256:{}", "5".repeat(64)),
        provider: "openai-api".into(),
        model: "gpt-5.2-2025-12-11".into(),
        trial_ids: vec!["trial-a".into()],
        max_trial_generations: 2,
        max_trial_counts: 2,
        max_trial_input_tokens: 30,
        max_trial_output_tokens: 20,
        max_trial_total_tokens: 50,
        max_trial_seconds: 120,
        max_trial_cost_usd: "0.01".into(),
        max_study_cost_usd: "0.02".into(),
    }
}

#[test]
fn python_and_rust_agree_on_exact_canonical_bytes_and_digest() {
    let value: Value = serde_json::from_slice(GOLDEN).unwrap();
    let (projection, digest) = parse_rehearsal(GOLDEN, &scope(), "trial-a", 1893553445).unwrap();
    assert_eq!(digest, DIGEST);
    assert_eq!(projection.mode, "candidate-rehearsal");
    assert_eq!(
        projection.gateway.binary_digest,
        format!("sha256:{}", "d".repeat(64))
    );
    assert_eq!(
        agentguard_stage1_metering_gateway::canonical(&value).unwrap(),
        GOLDEN
    );
}

#[test]
fn every_bound_field_mutation_and_noncanonical_encoding_fails() {
    let original: Value = serde_json::from_slice(GOLDEN).unwrap();
    for pointer in [
        "/authorization/digest",
        "/authorization/expires_at_epoch",
        "/study_id",
        "/trial_id",
        "/replay_id",
        "/plan_digest",
        "/profile/digest",
        "/fixture/digest",
        "/gateway/subject",
        "/gateway/canonical_identity",
        "/gateway/binary_digest",
        "/agent/subject",
        "/agent/canonical_identity",
        "/provider/model",
        "/provider/destination",
        "/credential_env_name",
        "/pricing_digest",
        "/ledger/scope_digest",
        "/limits/max_trial_seconds",
        "/evidence/schema",
        "/redaction_digest",
        "/run_nonce",
    ] {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = Value::String("changed".into());
        let raw = agentguard_stage1_metering_gateway::canonical(&value).unwrap();
        assert!(
            parse_rehearsal(&raw, &scope(), "trial-a", 1893553445).is_err(),
            "{pointer}"
        );
    }
    let mut value = original.clone();
    value["mode"] = "published-live".into();
    assert!(
        parse_rehearsal(
            &agentguard_stage1_metering_gateway::canonical(&value).unwrap(),
            &scope(),
            "trial-a",
            1893553445,
        )
        .is_err()
    );
    for raw in [
        GOLDEN[..GOLDEN.len() - 1].to_vec(),
        [GOLDEN, b" "].concat(),
        GOLDEN.windows(24).next().unwrap().to_vec(),
        b"{\"schema\":1,\"schema\":2}\n".to_vec(),
        b"{\"schema_version\":1.0}\n".to_vec(),
        b"{\"schema_version\":18446744073709551616}\n".to_vec(),
        b"{\"schema\":\"\xff\"}\n".to_vec(),
    ] {
        assert!(parse_rehearsal(&raw, &scope(), "trial-a", 1893553445).is_err());
    }
    assert!(parse_rehearsal(GOLDEN, &scope(), "trial-a", 1893557045).is_err());
}
