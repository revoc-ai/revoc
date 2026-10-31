use http::HeaderMap;

use crate::depth::{
    check_depth, extract_depth, set_outgoing_depth, MAX_GOVERNANCE_DEPTH, REVOC_DEPTH_HEADER,
};

#[test]
fn test_missing_depth_header_is_zero() {
    let headers = HeaderMap::new();
    assert_eq!(extract_depth(&headers), 0);
}

#[test]
fn test_depth_header_parsed_correctly() {
    let mut headers = HeaderMap::new();
    headers.insert(REVOC_DEPTH_HEADER, "5".parse().unwrap());
    assert_eq!(extract_depth(&headers), 5);
}

#[test]
fn test_depth_9_passes() {
    assert!(check_depth(9).is_ok());
    assert!(check_depth(0).is_ok());
    assert!(check_depth(1).is_ok());
    assert!(check_depth(MAX_GOVERNANCE_DEPTH - 1).is_ok());
}

#[test]
fn test_depth_10_returns_error() {
    let err = check_depth(MAX_GOVERNANCE_DEPTH);
    assert!(err.is_err());
    match err.unwrap_err() {
        revoc_core::RevocError::GovernanceDepthExceeded { depth } => {
            assert_eq!(depth, MAX_GOVERNANCE_DEPTH);
        }
        _ => panic!("Expected GovernanceDepthExceeded"),
    }
}

#[test]
fn test_depth_error_code_correct() {
    let _err = check_depth(10).unwrap_err();
    let resp = revoc_core::RevocErrorResponse::depth_exceeded("trace", 10, "http://localhost:3000");
    assert_eq!(resp.error.code, "REVOC_GOVERNANCE_DEPTH_EXCEEDED");
    assert!(resp.error.message.contains("10/10"));
}

#[test]
fn test_outgoing_depth_incremented_on_upstream() {
    let mut headers = HeaderMap::new();
    set_outgoing_depth(&mut headers, 3);
    let value = headers.get(REVOC_DEPTH_HEADER).unwrap().to_str().unwrap();
    assert_eq!(value, "4");
}

#[test]
fn test_outgoing_depth_from_zero() {
    let mut headers = HeaderMap::new();
    set_outgoing_depth(&mut headers, 0);
    let value = headers.get(REVOC_DEPTH_HEADER).unwrap().to_str().unwrap();
    assert_eq!(value, "1");
}

#[test]
fn test_outgoing_depth_saturates_at_u8_max() {
    let mut headers = HeaderMap::new();
    set_outgoing_depth(&mut headers, 255);
    // saturating_add(1) on u8::MAX should stay at 255
    let value = headers.get(REVOC_DEPTH_HEADER).unwrap().to_str().unwrap();
    assert_eq!(value, "255");
}

#[test]
fn test_depth_exceeded_http_status() {
    use revoc_core::RevocError;
    let err = RevocError::GovernanceDepthExceeded { depth: 10 };
    assert_eq!(err.http_status(), 503);
}
