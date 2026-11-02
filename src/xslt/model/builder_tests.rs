use super::{Document, ParseBudget};
use crate::{BudgetKind, Error};

#[test]
fn building_text_charges_the_parser_work_its_parse_charges() {
    // Copying character data into the tree is parser work: a budget that
    // admits only one pass over the text refuses the parse at the copy, and
    // must refuse the build of the same markup there too.
    let text = format!("<r>{}</r>", "x".repeat(1000));
    let budget = ParseBudget::new(1 << 20, 16, 8, 0, 0, 1 << 20).with_parse_work_bytes(text.len());
    let parsed = Document::parse_with_budget(&text, None, budget);
    assert!(
        matches!(
            parsed,
            Err(Error::Budget {
                kind: BudgetKind::ParseWorkBytes,
                ..
            })
        ),
        "{parsed:?}"
    );
    let content = "x".repeat(1000);
    let built = Document::build_with_budget_reported(None, budget, text.len(), |builder| {
        builder.start_element((None, "r"), [], [], 1)?;
        builder.text(&[&content], 1)?;
        builder.end_element()
    });
    assert_eq!(
        built.usage,
        Document::parse_with_budget_reported(&text, None, budget).usage
    );
    assert_eq!(
        built.outcome.err().map(|error| error.to_string()),
        parsed.err().map(|error| error.to_string())
    );
}
