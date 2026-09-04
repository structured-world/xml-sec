use crate::lexical::{is_ncname_char, is_ncname_start};

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
        while open < source.len() && source[open..].chars().next().is_some_and(is_xpath_space) {
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

pub(crate) fn unprefixed_function_calls(source: &str, name: &str) -> Vec<FunctionCall> {
    let mut calls = Vec::new();
    scan_unprefixed_function_calls(source, name, |start, open, close| {
        calls.push(FunctionCall {
            start,
            end: close + 1,
            arguments: split_function_arguments(&source[open + 1..close]),
            namespace: String::new(),
            local: name.to_owned(),
            display_name: name.to_owned(),
        });
        false
    });
    calls
}

pub(crate) fn has_unprefixed_function_call(source: &str, name: &str) -> bool {
    scan_unprefixed_function_calls(source, name, |_, _, _| true)
}

fn scan_unprefixed_function_calls(
    source: &str,
    name: &str,
    mut visit: impl FnMut(usize, usize, usize) -> bool,
) -> bool {
    let mut calls = Vec::<(usize, usize, Option<usize>)>::new();
    let mut parentheses = Vec::<Option<usize>>::new();
    let mut quote = None;
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
            parentheses.push(None);
            cursor += 1;
            continue;
        }
        if character == ')' {
            cursor += 1;
            if let Some(Some(call)) = parentheses.pop() {
                calls[call].2 = Some(cursor - 1);
            }
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
        if qualified {
            continue;
        }
        if &source[start..cursor] != name {
            continue;
        }
        let mut open = cursor;
        while open < source.len() && source[open..].chars().next().is_some_and(is_xpath_space) {
            open += source[open..]
                .chars()
                .next()
                .expect("cursor is inside source")
                .len_utf8();
        }
        if !source[open..].starts_with('(') {
            continue;
        }
        let call = calls.len();
        calls.push((start, open, None));
        parentheses.push(Some(call));
        cursor = open + 1;
    }
    for (start, open, close) in calls {
        if let Some(close) = close
            && visit(start, open, close)
        {
            return true;
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

fn is_xpath_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn split_function_arguments(source: &str) -> Vec<String> {
    if source.trim().is_empty() {
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
                arguments.push(source[start..offset].trim().to_owned());
                start = offset + 1;
            }
            _ => {}
        }
    }
    arguments.push(source[start..].trim().to_owned());
    arguments
}

#[cfg(test)]
mod tests {
    use super::{
        has_unprefixed_function_call, innermost_namespaced_call, unprefixed_function_calls,
    };

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
        assert!(unprefixed_function_calls("x:key()", "key").is_empty());
        assert_eq!(unprefixed_function_calls("key()", "key").len(), 1);
    }

    #[test]
    fn unprefixed_call_detection_ignores_literals_and_qualified_names() {
        // Pattern context selection must react only to an actual unprefixed function call.
        assert!(has_unprefixed_function_call("current ()/item", "current"));
        assert!(!has_unprefixed_function_call("'current()'", "current"));
        assert!(!has_unprefixed_function_call("x:current()", "current"));
    }

    #[test]
    fn unprefixed_call_discovery_is_linear_at_extreme_depth() {
        // Deep caller-controlled expressions must not trigger one complete rescan per call.
        let source = format!("{}1{}", "key(".repeat(1_000), ")".repeat(1_000));
        let calls = unprefixed_function_calls(&source, "key");
        assert_eq!(calls.len(), 1_000);
        assert_eq!(&source[calls[0].start..calls[0].end], source);
        let innermost = calls.last().expect("nested expression has calls");
        assert_eq!(&source[innermost.start..innermost.end], "key(1)");
    }
}
