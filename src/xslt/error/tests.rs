use super::*;

#[test]
fn decoded_size_limits_keep_the_budget_error_contract() {
    let error = decoded_xml_error(xml_sec_xml_input::Error::DecodedLimit {
        maximum: 8,
        actual: 9,
    });
    assert_eq!(error.kind(), ErrorKind::Budget);
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: 8,
            actual: 9,
        }
    ));
}
