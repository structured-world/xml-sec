use crate::lexical::{is_ncname_char, is_ncname_start, is_xml_whitespace, trim_xml_whitespace};
use crate::{
    Result,
    budget::{Meter, reserve_temporary_vec_slot},
};

pub(crate) struct FunctionCall {
    pub start: usize,
    pub end: usize,
    pub arguments: Vec<String>,
    pub namespace: String,
    pub local: String,
    pub display_name: String,
}

pub(crate) fn innermost_namespaced_call(
    source: &str,
    namespaces: &[(String, String)],
    accepts: impl Fn(&str, &str) -> bool + Copy,
) -> Option<FunctionCall> {
    struct PendingCall {
        start: usize,
        arguments_start: usize,
        namespace: usize,
        local_start: usize,
        local_end: usize,
        display_end: usize,
    }

    let mut parentheses = Vec::new();
    let mut quote = None;
    let mut cursor = 0;
    while cursor < source.len() {
        let character = source[cursor..].chars().next()?;
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            cursor += character.len_utf8();
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            cursor += character.len_utf8();
            continue;
        }
        if character == '(' {
            parentheses.push(None);
            cursor += 1;
            continue;
        }
        if character == ')' {
            cursor += 1;
            let Some(pending) = parentheses.pop() else {
                continue;
            };
            if let Some(PendingCall {
                start,
                arguments_start,
                namespace,
                local_start,
                local_end,
                display_end,
            }) = pending
            {
                return Some(FunctionCall {
                    start,
                    end: cursor,
                    arguments: split_function_arguments(&source[arguments_start..cursor - 1]),
                    namespace: namespaces[namespace].1.clone(),
                    local: source[local_start..local_end].to_owned(),
                    display_name: source[start..display_end].to_owned(),
                });
            }
            continue;
        }
        if !is_ncname_start(character) {
            cursor += character.len_utf8();
            continue;
        }
        let start = cursor;
        let (end, qualified) = lexical_name_end(source, start)?;
        cursor = end;
        if !qualified {
            continue;
        }
        let lexical = &source[start..cursor];
        let Some((prefix, local)) = lexical.split_once(':') else {
            continue;
        };
        if local.contains(':') {
            continue;
        }
        let Some(namespace) = namespaces
            .iter()
            .position(|(candidate, _)| candidate == prefix)
        else {
            continue;
        };
        if !accepts(&namespaces[namespace].1, local) {
            continue;
        }
        let mut open = cursor;
        while open < source.len() && source[open..].chars().next().is_some_and(is_xml_whitespace) {
            open += source[open..].chars().next()?.len_utf8();
        }
        if !source[open..].starts_with('(') {
            continue;
        }
        parentheses.push(Some(PendingCall {
            start,
            arguments_start: open + 1,
            namespace,
            local_start: start + prefix.len() + 1,
            local_end: cursor,
            display_end: cursor,
        }));
        cursor = open + 1;
    }
    None
}

pub(crate) fn metered_unprefixed_call_arguments<'a>(
    source: &'a str,
    name: &str,
    meter: &mut Meter,
) -> Result<(Vec<(usize, &'a str)>, usize)> {
    let mut parentheses = Vec::<Option<(usize, usize)>>::new();
    let mut parentheses_bytes = 0;
    let mut arguments = Vec::<(usize, &str)>::new();
    let mut arguments_bytes = 0;
    let result = (|| {
        let mut quote = None;
        let mut cursor = 0;
        while cursor < source.len() {
            let character = source[cursor..].chars().next().expect("character boundary");
            if let Some(active) = quote {
                if character == active {
                    quote = None;
                }
                cursor += character.len_utf8();
                continue;
            }
            if matches!(character, '\'' | '"') {
                quote = Some(character);
                cursor += character.len_utf8();
                continue;
            }
            if character == '(' {
                reserve_temporary_vec_slot(&mut parentheses, meter, &mut parentheses_bytes)?;
                parentheses.push(None);
                cursor += 1;
                continue;
            }
            if character == ')' {
                if let Some(Some((start, open))) = parentheses.pop() {
                    reserve_temporary_vec_slot(&mut arguments, meter, &mut arguments_bytes)?;
                    arguments.push((start, &source[open + 1..cursor]));
                }
                cursor += 1;
                continue;
            }
            if !is_ncname_start(character) {
                cursor += character.len_utf8();
                continue;
            }
            let start = cursor;
            let Some((end, qualified)) = lexical_name_end(source, start) else {
                break;
            };
            cursor = end;
            if qualified || &source[start..end] != name {
                continue;
            }
            let mut open = cursor;
            while open < source.len()
                && source[open..].chars().next().is_some_and(is_xml_whitespace)
            {
                open += source[open..]
                    .chars()
                    .next()
                    .expect("character boundary")
                    .len_utf8();
            }
            if source[open..].starts_with('(') {
                reserve_temporary_vec_slot(&mut parentheses, meter, &mut parentheses_bytes)?;
                parentheses.push(Some((start, open)));
                cursor = open + 1;
            }
        }
        arguments.sort_unstable_by_key(|(start, _)| *start);
        Ok(())
    })();
    drop(parentheses);
    meter.release_owned_bytes(parentheses_bytes);
    if let Err(error) = result {
        meter.release_owned_bytes(arguments_bytes);
        return Err(error);
    }
    Ok((arguments, arguments_bytes))
}

pub(crate) fn has_unprefixed_function_call(source: &str, name: &str) -> bool {
    let mut quote = None;
    let mut depth = 0usize;
    let mut candidate_depth = None;
    let mut cursor = 0;
    while cursor < source.len() {
        let Some(character) = source[cursor..].chars().next() else {
            break;
        };
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            cursor += character.len_utf8();
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            cursor += character.len_utf8();
            continue;
        }
        if character == '(' {
            depth += 1;
            cursor += 1;
            continue;
        }
        if character == ')' {
            if candidate_depth == Some(depth) {
                return true;
            }
            depth = depth.saturating_sub(1);
            cursor += 1;
            continue;
        }
        if !is_ncname_start(character) {
            cursor += character.len_utf8();
            continue;
        }
        let start = cursor;
        let Some((end, qualified)) = lexical_name_end(source, start) else {
            break;
        };
        cursor = end;
        if qualified || &source[start..cursor] != name {
            continue;
        }
        while cursor < source.len()
            && source[cursor..]
                .chars()
                .next()
                .is_some_and(is_xml_whitespace)
        {
            cursor += source[cursor..]
                .chars()
                .next()
                .expect("cursor is inside source")
                .len_utf8();
        }
        if source[cursor..].starts_with('(') {
            depth += 1;
            candidate_depth = Some(depth);
            cursor += 1;
        }
    }
    false
}

fn lexical_name_end(source: &str, start: usize) -> Option<(usize, bool)> {
    let first = source[start..].chars().next()?;
    if !is_ncname_start(first) {
        return None;
    }
    let mut cursor = start + first.len_utf8();
    while cursor < source.len() {
        let next = source[cursor..].chars().next()?;
        if !is_ncname_char(next) {
            break;
        }
        cursor += next.len_utf8();
    }

    let mut qualified = false;
    while source[cursor..].starts_with(':') {
        qualified = true;
        cursor += 1;
        let Some(local_start) = source[cursor..].chars().next() else {
            break;
        };
        if !is_ncname_start(local_start) {
            continue;
        }
        cursor += local_start.len_utf8();
        while cursor < source.len() {
            let next = source[cursor..].chars().next()?;
            if !is_ncname_char(next) {
                break;
            }
            cursor += next.len_utf8();
        }
    }
    Some((cursor, qualified))
}

fn split_function_arguments(source: &str) -> Vec<String> {
    if trim_xml_whitespace(source).is_empty() {
        return Vec::new();
    }
    let mut arguments = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut quote = None;
    for (offset, character) in source.char_indices() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                arguments.push(trim_xml_whitespace(&source[start..offset]).to_owned());
                start = offset + 1;
            }
            _ => {}
        }
    }
    arguments.push(trim_xml_whitespace(&source[start..]).to_owned());
    arguments
}

#[cfg(test)]
mod tests {
    use super::{
        has_unprefixed_function_call, innermost_namespaced_call, metered_unprefixed_call_arguments,
    };
    use crate::budget::{ExecutionBudget, Meter};

    fn metered_calls<'a>(source: &'a str, name: &str) -> Vec<(usize, &'a str)> {
        let mut meter = Meter::new(
            ExecutionBudget {
                source_bytes: usize::MAX,
                external_documents: usize::MAX,
                recursion_depth: usize::MAX,
                xpath_evaluations: usize::MAX,
                xpath_operations: usize::MAX,
                extension_operations: usize::MAX,
                pattern_evaluations: usize::MAX,
                template_applications: usize::MAX,
                sort_comparisons: usize::MAX,
                key_entries: usize::MAX,
                result_nodes: usize::MAX,
                serialized_bytes: usize::MAX,
                messages: usize::MAX,
                owned_bytes: usize::MAX,
            },
            0,
        )
        .expect("test meter");
        let (calls, reservation) = metered_unprefixed_call_arguments(source, name, &mut meter)
            .expect("call scan fits the test budget");
        meter.release_owned_bytes(reservation);
        calls
    }

    #[test]
    fn namespaced_call_discovery_is_iterative_at_extreme_depth() {
        let source = format!("{}1{}", "x:f(".repeat(1_000), ")".repeat(1_000));
        let call = innermost_namespaced_call(
            &source,
            &[("x".into(), "urn:test".into())],
            |namespace, local| namespace == "urn:test" && local == "f",
        )
        .expect("nested call is discovered");
        assert_eq!(&source[call.start..call.end], "x:f(1)");
    }

    #[test]
    fn namespaced_call_discovery_scans_mixed_nesting_once() {
        // Extension discovery must remain linear when accepted and ordinary calls are interleaved.
        let source =
            format!("plain({}x:target(')'))", "x:outer(plain(".repeat(1_000)) + &"))".repeat(1_000);
        let call = innermost_namespaced_call(
            &source,
            &[("x".into(), "urn:test".into())],
            |namespace, _| namespace == "urn:test",
        )
        .expect("innermost accepted call is discovered");
        assert_eq!(&source[call.start..call.end], "x:target(')')");
    }

    #[test]
    fn namespaced_call_discovery_accepts_complete_ncname_grammar() {
        // XML NameStartChar includes U+200C; extension discovery must share
        // the same QName grammar as stylesheet compilation.
        let prefix = "\u{200c}";
        let source = format!("{prefix}:function()");
        let call = innermost_namespaced_call(
            &source,
            &[(prefix.into(), "urn:test".into())],
            |namespace, local| namespace == "urn:test" && local == "function",
        )
        .expect("valid Unicode-prefixed call is discovered");
        assert_eq!(&source[call.start..call.end], source);
    }

    #[test]
    fn unprefixed_call_discovery_excludes_qualified_names() {
        // A prefixed extension function whose local name matches a core function
        // must not activate the core function's compile-time or runtime behavior.
        assert!(metered_calls("x:key()", "key").is_empty());
        assert_eq!(metered_calls("key()", "key").len(), 1);
    }

    #[test]
    fn function_arguments_preserve_non_xpath_whitespace() {
        // XPath 1.0 section 3.7 limits ExprWhitespace to XML S; NBSP remains expression input.
        // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
        let calls = metered_calls("key(\u{a0}'value')", "key");
        assert_eq!(calls[0].1, "\u{a0}'value'");
    }

    #[test]
    fn unprefixed_call_detection_ignores_literals_and_qualified_names() {
        // Pattern context selection must react only to an actual unprefixed function call.
        assert!(has_unprefixed_function_call("current ()/item", "current"));
        assert!(!has_unprefixed_function_call("'current()'", "current"));
        assert!(!has_unprefixed_function_call("x:current()", "current"));
        assert!(!has_unprefixed_function_call("current(", "current"));
        assert!(has_unprefixed_function_call(
            "current(('current())'))",
            "current"
        ));
    }

    #[test]
    fn unprefixed_boolean_detection_does_not_retain_matches() {
        // Boolean capability checks must scan a caller-sized expression without retaining every
        // lexical call; the first complete match is sufficient.
        let source = "ordinary(),".repeat(100_000) + "current()";
        assert!(has_unprefixed_function_call(&source, "current"));
    }

    #[test]
    fn unprefixed_call_discovery_is_linear_at_extreme_depth() {
        // Deep caller-controlled expressions must not trigger one complete rescan per call.
        let source = format!("{}1{}", "key(".repeat(1_000), ")".repeat(1_000));
        let calls = metered_calls(&source, "key");
        assert_eq!(calls.len(), 1_000);
        assert_eq!(calls[0].0, 0);
        let innermost = calls.last().expect("nested expression has calls");
        assert_eq!(innermost.1, "1");
    }

    #[test]
    fn key_call_scan_reserves_temporary_stack_before_growing() {
        let mut budget = ExecutionBudget {
            source_bytes: 0,
            external_documents: 0,
            recursion_depth: 0,
            xpath_evaluations: 0,
            xpath_operations: 0,
            extension_operations: 0,
            pattern_evaluations: 0,
            template_applications: 0,
            sort_comparisons: 0,
            key_entries: 0,
            result_nodes: 0,
            serialized_bytes: 0,
            messages: 0,
            owned_bytes: 0,
        };
        let mut meter = Meter::new(budget, 0).expect("zero-size source");
        assert!(metered_unprefixed_call_arguments("key('name', /)", "key", &mut meter).is_err());
        budget.owned_bytes = 1024;
        let mut meter = Meter::new(budget, 0).expect("meter");
        let (calls, reservation) =
            metered_unprefixed_call_arguments("key('name', /)", "key", &mut meter)
                .expect("sufficient budget");
        assert_eq!(calls, [(0, "'name', /")]);
        meter.release_owned_bytes(reservation);
    }
}
