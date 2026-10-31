fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|e| {
        eprintln!("FATAL: CARGO_MANIFEST_DIR not set: {e}");
        std::process::exit(1)
    });
    let policies = std::path::Path::new(&dir).join("../../policies/default");
    for f in &[
        "main.rego",
        "llm_governance.rego",
        "mcp_governance.rego",
        "quota_governance.rego",
        "data.json",
    ] {
        let p = policies.join(f);
        assert!(p.exists(), "Required policy file missing: {}", p.display());
        println!("cargo:rerun-if-changed={}", p.display());
    }
}
