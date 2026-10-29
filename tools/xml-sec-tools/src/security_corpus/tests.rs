use super::{audit, check, collapse_whitespace, disposition_table, inventory, safe_path};
use serde_json::{Value, json};

fn nvd(products: &[&str], data: &Value) -> Vec<(String, Value)> {
    products
        .iter()
        .map(|product| ((*product).to_owned(), data.clone()))
        .collect()
}

#[test]
fn inventory_retains_keyword_false_positives_and_all_contributing_sources() {
    // An audit cannot silently discard an advisory merely because it names a wrapper.
    let data = json!({ "vulnerabilities": [{ "cve": {
        "id": "CVE-2025-1", "published": "2025-01-01", "vulnStatus": "Rejected",
        "descriptions": [{ "lang": "en", "value": "wrapper, not native library" }],
        "references": [{ "url": "https://example.org/fix" }],
    } }] });
    let debian = json!({ "xmlsec1": { "CVE-2009-0217": { "description": "HMAC truncation" } } });
    let rows = inventory(&nvd(&["libxml2", "libxslt", "xmlsec"], &data), &debian).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["products"], json!(["libxml2", "libxslt", "xmlsec"]));
    assert_eq!(rows[1]["status"], "Rejected");
    assert_eq!(rows[1]["references"], json!(["https://example.org/fix"]));
    assert_eq!(rows[0]["sources"], json!(["debian"]));
    assert_eq!(rows[0]["description"], "HMAC truncation");
}

#[test]
fn corpus_paths_cannot_escape_their_pinned_root() {
    // A manifest line must never reach outside the corpus directory.
    for path in [
        "../secret",
        "/etc/passwd",
        "a/../../secret",
        "a\\b",
        "a//b",
        "",
    ] {
        assert!(safe_path(path).is_err(), "{path}");
    }
    assert_eq!(
        safe_path("test/errors/781205.xml").unwrap(),
        "test/errors/781205.xml"
    );
}

#[test]
fn partial_advisory_downloads_and_unclassified_records_fail_closed() {
    // A successful HTTP response is not evidence that pagination is complete.
    let partial = json!({ "totalResults": 2, "vulnerabilities": [] });
    assert!(
        inventory(&nvd(&["libxml2"], &partial), &json!({}))
            .unwrap_err()
            .contains("all NVD pages")
    );
    let table = disposition_table(&json!([])).unwrap();
    assert!(
        audit(&json!({ "records": [{ "id": "CVE-2099-9999" }] }), &table)
            .unwrap_err()
            .contains("every advisory")
    );
    let duplicated = json!([
        { "status": "a", "ids": ["CVE-2009-0217"] },
        { "status": "b", "ids": ["CVE-2009-0217"] },
    ]);
    assert!(
        disposition_table(&duplicated)
            .unwrap_err()
            .contains("duplicate disposition")
    );
}

#[test]
fn audit_output_binds_the_complete_advisory_snapshot() {
    // Changing evidence text without regenerating the report must be detectable.
    let table = disposition_table(&json!([{
        "status": "boundary-regression", "mechanism": "m", "evidence": "e", "reason": "r",
        "ids": ["CVE-2009-0217"],
    }]))
    .unwrap();
    let mut data = json!({ "records": [{ "id": "CVE-2009-0217", "description": "original" }] });
    let before: Value = serde_json::from_str(&audit(&data, &table).unwrap()).unwrap();
    data["records"][0]["description"] = json!("changed");
    let after: Value = serde_json::from_str(&audit(&data, &table).unwrap()).unwrap();
    assert_ne!(before["advisorySha256"], after["advisorySha256"]);
    assert_eq!(before["records"], after["records"]);
    assert_eq!(
        before["records"][0],
        json!({ "id": "CVE-2009-0217", "status": "boundary-regression", "mechanism": "m", "evidence": "e", "reason": "r" })
    );
}

#[test]
fn cpe_and_alias_searches_retain_evidence_without_duplicating_an_advisory() {
    // A CPE hit must merge into the real product while an alias remains visible.
    let data = json!({ "totalResults": 1, "vulnerabilities": [{ "cve": {
        "id": "CVE-2025-1", "descriptions": [{ "lang": "en", "value": "source evidence" }], "references": [],
    } }] });
    let rows = inventory(
        &nvd(&["cpe-libxml2", "libxml2", "libxml"], &data),
        &json!({}),
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["products"], json!(["libxml2", "libxml"]));
}

#[test]
fn descriptions_keep_their_ends_when_whitespace_collapses() {
    // The generated page must match the earlier report text exactly.
    assert_eq!(collapse_whitespace(" a \n\t b "), " a b ");
}

#[test]
fn the_committed_corpus_audit_and_inventory_are_current() {
    // Pinned payloads, dispositions and both generated reports must agree.
    assert!(check().unwrap().ends_with("upstream files verified"));
}
