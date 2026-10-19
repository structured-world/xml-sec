#[test]
fn date_lexical_components_require_complete_unsigned_fields() {
    // Reject trailing year garbage and signed timezone components, not valid timezone signs.
    for input in [
        "2000garbage",
        "2000 ",
        "2000-01-01+00:-1",
        "2000-01-01+-1:00",
        "2000-01-01+00:+1",
    ] {
        assert!(super::DateValue::parse(input).is_none(), "accepted {input}");
    }
    for input in [
        "2000",
        "-2000",
        "2000Z",
        "2000-01-01+14:00",
        "2000-01-01-00:01",
    ] {
        assert!(super::DateValue::parse(input).is_some(), "rejected {input}");
    }
}
use super::{DateFunction, DateValue, DurationValue, Operation, split_timezone};
use sxd_document_no_unsafe::Package;
use sxd_xpath_no_unsafe::{Context, Value, function::Function, nodeset};

#[test]
fn date_extensions_meter_every_xpath_string_coercion() {
    // EXSLT date functions inspect the XPath string-value even when parsing returns an empty
    // result, so the temporary materialization must cross the operation allocation gate.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    root.append_child(document.create_text("2000-01-01"));
    document.root().append_child(root);
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(root);

    let mut context = Context::new();
    context.set_string_allocation_limit(0);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    let error = DateFunction(
        Operation::Date,
        Some(std::sync::Arc::new(crate::FixedClock::new(
            time::OffsetDateTime::UNIX_EPOCH,
        ))),
    )
    .evaluate(&evaluation, vec![Value::Nodeset(nodes)])
    .expect_err("date input coercion must cross the allocation gate");
    assert!(error.to_string().contains("allocation budget"));
}

#[test]
fn end_of_day_lexical_forms_normalize_without_accepting_later_times() {
    // End-of-day advances a dateTime but is the same midnight value for standalone time;
    // no non-zero minute or second spelling may enter that normalization path.
    assert_eq!(
        DateValue::parse("2000-12-31T24:00:00Z")
            .expect("XML Schema end-of-day form parses")
            .render(),
        "2001-01-01T00:00:00Z"
    );
    assert_eq!(
        DateValue::parse("24:00:00.000+02:00")
            .expect("standalone end-of-day time parses")
            .time_string()
            .as_deref(),
        Some("00:00:00+02:00")
    );
    for invalid in [
        "24:00:00.1",
        "24:00:00.0000000000000000000000001",
        "24:00:01",
        "24:01:00",
        "12:34:56.",
        "2000-01-01T12:34:56.",
    ] {
        assert!(DateValue::parse(invalid).is_none(), "accepted {invalid}");
    }
}

#[test]
fn month_day_rejects_out_of_range_months() {
    assert!(DateValue::parse("--50-15").is_none());
    assert!(DateValue::parse("--02-29").is_some());
}

#[test]
fn timezone_probe_never_slices_inside_utf8() {
    assert_eq!(split_timezone("é12345"), Some(("é12345", None)));
}

#[test]
fn extreme_duration_and_date_arithmetic_fail_closed() {
    assert!(DurationValue::parse("P999999999999999999999Y").is_none());
    let maximum =
        DateValue::parse("9223372036854775807-12-31").expect("maximum schema year parses");
    assert!(maximum.add(DurationValue::from_seconds(86_400.0)).is_none());
}

#[test]
fn duration_seconds_require_an_integer_part() {
    // XML Schema Part 2 section 3.2.6.1 requires the seconds numeral before an optional
    // decimal fraction: https://www.w3.org/TR/xmlschema-2/#duration-lexical-representation
    assert!(DurationValue::parse("PT.5S").is_none());
}

#[test]
fn strict_duration_seconds_require_a_fractional_digit() {
    // XML Schema 1.0 erratum E2-23 requires at least one digit on both sides of the decimal
    // point. The libxslt-only parser may preserve its historical trailing-point extension.
    // https://www.w3.org/2001/05/xmlschema-errata#e2-23
    assert!(DurationValue::parse("PT1.S").is_none());
    assert!(DurationValue::parse_libxslt_seconds("PT1.S").is_some());
}

#[test]
fn duration_render_preserves_nonzero_subnanosecond_values() {
    for lexical in ["PT0.0000000001S", "PT0.0000000000001S"] {
        let duration = DurationValue::parse(lexical).expect("valid duration parses");
        assert_ne!(duration.render(), "P");
        assert_eq!(duration.render(), lexical);
    }
}

#[test]
fn duration_render_rejects_unrepresentable_finite_seconds() {
    // Every operation funnels through render, so arithmetic cannot saturate a float-to-int
    // conversion into a plausible but incorrect duration.
    assert_eq!(DurationValue::from_seconds(1.0e30).render(), "");
    assert_eq!(DurationValue::from_seconds(-1.0e30).render(), "");
}
