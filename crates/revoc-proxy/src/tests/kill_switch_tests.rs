use std::sync::Arc;

use revoc_core::CallerContext;

use crate::kill_switch::{KillSwitchEntry, KillSwitchScope, KillSwitchState};

fn make_state() -> Arc<KillSwitchState> {
    Arc::new(KillSwitchState::new())
}

fn make_caller(org_id: &str, caller_id: &str) -> CallerContext {
    CallerContext {
        org_id: org_id.into(),
        caller_id: caller_id.into(),
        ..Default::default()
    }
}

fn entry(scope: KillSwitchScope) -> KillSwitchEntry {
    KillSwitchEntry {
        activated_by: "test".into(),
        activated_at: chrono::Utc::now(),
        reason: "test".into(),
        scope,
    }
}

#[test]
fn test_inactive_by_default() {
    let ks = make_state();
    let caller = make_caller("org1", "caller1");
    assert!(!ks.is_active_for(&caller));
}

#[test]
fn test_active_global_blocks_all_callers() {
    let ks = make_state();
    ks.activate(entry(KillSwitchScope::Global));
    assert!(ks.is_active_for(&make_caller("org-a", "caller-1")));
    assert!(ks.is_active_for(&make_caller("org-b", "caller-2")));
}

#[test]
fn test_org_scope_blocks_org_a_not_b() {
    let ks = make_state();
    ks.activate(entry(KillSwitchScope::Org("org-a".into())));
    assert!(ks.is_active_for(&make_caller("org-a", "any-caller")));
    assert!(!ks.is_active_for(&make_caller("org-b", "any-caller")));
}

#[test]
fn test_caller_scope_blocks_specific_caller() {
    let ks = make_state();
    ks.activate(entry(KillSwitchScope::Caller("bad-caller".into())));
    assert!(ks.is_active_for(&make_caller("org1", "bad-caller")));
    assert!(!ks.is_active_for(&make_caller("org1", "good-caller")));
}

#[test]
fn test_deactivate_restores_traffic() {
    let ks = make_state();
    let scope = KillSwitchScope::Global;
    ks.activate(entry(scope.clone()));
    assert!(ks.is_active_for(&make_caller("org1", "c1")));

    ks.deactivate(&scope);
    assert!(!ks.is_active_for(&make_caller("org1", "c1")));
}

#[test]
fn test_deactivate_org_scope() {
    let ks = make_state();
    let scope = KillSwitchScope::Org("org-x".into());
    ks.activate(entry(scope.clone()));
    assert!(ks.is_active_for(&make_caller("org-x", "any")));

    ks.deactivate(&scope);
    assert!(!ks.is_active_for(&make_caller("org-x", "any")));
}

#[test]
fn test_snapshot_reflects_state() {
    let ks = make_state();
    ks.activate(entry(KillSwitchScope::Global));
    ks.activate(entry(KillSwitchScope::Org("org-1".into())));

    let snap = ks.status_snapshot();
    assert!(snap.global);
    assert_eq!(snap.by_org.len(), 1);
    assert!(snap.by_caller.is_empty());
}

#[test]
fn test_multiple_org_scopes_independent() {
    let ks = make_state();
    ks.activate(entry(KillSwitchScope::Org("org-a".into())));
    ks.activate(entry(KillSwitchScope::Org("org-b".into())));

    assert!(ks.is_active_for(&make_caller("org-a", "c")));
    assert!(ks.is_active_for(&make_caller("org-b", "c")));

    ks.deactivate(&KillSwitchScope::Org("org-a".into()));
    assert!(!ks.is_active_for(&make_caller("org-a", "c")));
    assert!(ks.is_active_for(&make_caller("org-b", "c")));
}
