#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use revoc_core::{CallerContext, EnforcementMode, InspectionInput, RequestType};
use revoc_detector::DetectionEngine;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return,
    };

    let engine = DetectionEngine::new_for_testing();

    let input = InspectionInput {
        request_id: Uuid::now_v7().to_string(),
        request_type: RequestType::LlmRequest,
        raw_body: Bytes::copy_from_slice(data),
        parsed_messages: None,
        mcp_call: None,
        caller: CallerContext {
            org_id: "fuzz-org".into(),
            caller_id: "fuzz-caller".into(),
            team: None,
            agent_id: None,
            service_name: None,
            environment: "fuzz".into(),
            policy_profile: None,
            enforcement_mode: EnforcementMode::Enforce,
            governance_depth: 0,
            attributes: Default::default(),
        },
        governance_depth: 0,
    };

    // Must never panic regardless of input.
    let findings = rt.block_on(engine.detect(&input));
    let _ = findings;
});
