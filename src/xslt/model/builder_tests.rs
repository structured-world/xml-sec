use super::{Document, DocumentBuilder, ParseBudget};
use crate::{BudgetKind, Error};

const BUDGET: ParseBudget = ParseBudget::new(1 << 20, 64, 8, 0, 0, 1 << 20);

/// Constructs described to a builder.
type Construct = dyn FnOnce(&mut DocumentBuilder<'_, '_>) -> crate::Result<()>;

/// Build `text`'s constructs as `construct` describes them, and parse `text`.
fn built_and_parsed(
    text: &str,
    construct: impl FnOnce(&mut DocumentBuilder<'_, '_>) -> crate::Result<()>,
) -> (crate::Result<Document>, crate::Result<Document>) {
    (
        Document::build_with_budget_reported(None, BUDGET, text.len(), construct).outcome,
        Document::parse_with_budget(text, None, BUDGET),
    )
}

#[test]
fn a_line_end_split_around_an_empty_piece_is_one_line_end() {
    // XML 1.0 section 2.11 reads CR LF as one LF in the concatenated text,
    // however the run is split into pieces, empty ones included.
    let (built, parsed) = built_and_parsed("<r>a\r\nb</r>", |builder| {
        builder.start_element((None, "r"), [], [], 1)?;
        builder.text(&["a\r", "", "\nb"], 1)?;
        builder.end_element()
    });
    assert_eq!(built.expect("built"), parsed.expect("parsed"));
}

#[test]
fn constructs_a_parse_refuses_are_refused_when_built() {
    // The builder's refusals are those of a parse of the same text: invalid
    // element names, `--` or a trailing `-` in a comment, and an instruction
    // target `xml` or an invalid one, or `?>` in its value.
    let element = |name: &'static str| {
        move |builder: &mut DocumentBuilder<'_, '_>| {
            builder.start_element((None, name), [], [], 1)?;
            builder.end_element()
        }
    };
    let comment = |value: &'static str| {
        move |builder: &mut DocumentBuilder<'_, '_>| {
            builder.start_element((None, "r"), [], [], 1)?;
            builder.comment(&[value], 1)?;
            builder.end_element()
        }
    };
    let instruction = |target: &'static str, value: &'static str| {
        move |builder: &mut DocumentBuilder<'_, '_>| {
            builder.start_element((None, "r"), [], [], 1)?;
            builder.processing_instruction(target, Some(&[value]), 1)?;
            builder.end_element()
        }
    };
    let cases: [(&str, Box<Construct>); 6] = [
        ("<1a></1a>", Box::new(element("1a"))),
        ("<a:b:c></a:b:c>", Box::new(element("b:c"))),
        ("<r><!--a--b--></r>", Box::new(comment("a--b"))),
        ("<r><!--a---></r>", Box::new(comment("a-"))),
        ("<r><?xml v?></r>", Box::new(instruction("xml", "v"))),
        ("<r><?1t v?></r>", Box::new(instruction("1t", "v"))),
    ];
    for (text, construct) in cases {
        let (built, parsed) = built_and_parsed(text, construct);
        assert!(parsed.is_err(), "{text} parses");
        assert!(built.is_err(), "{text} is built: {built:?}");
    }
    // No text parses to an instruction value holding `?>`, which ends it.
    let (built, _) = built_and_parsed("<r><?t a?></r>", instruction("t", "a?>b"));
    assert!(built.is_err(), "{built:?}");
    // Their valid neighbours are accepted by both.
    let (built, parsed) = built_and_parsed("<r><!--a-b--><?xml-t v?></r>", |builder| {
        builder.start_element((None, "r"), [], [], 1)?;
        builder.comment(&["a-b"], 1)?;
        builder.processing_instruction("xml-t", Some(&["v"]), 1)?;
        builder.end_element()
    });
    assert_eq!(built.expect("built"), parsed.expect("parsed"));
}

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
