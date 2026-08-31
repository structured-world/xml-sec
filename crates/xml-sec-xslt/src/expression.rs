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
    let mut source = source;
    let mut source_offset = 0;
    loop {
        let call = first_namespaced_call(source, namespaces, accepts)?;
        let arguments_start = call.arguments_start;
        let arguments_end = call.end - 1;
        if first_namespaced_call(&source[arguments_start..arguments_end], namespaces, accepts)
            .is_some()
        {
            source_offset += arguments_start;
            source = &source[arguments_start..arguments_end];
            continue;
        }
        return Some(FunctionCall {
            start: source_offset + call.start,
            end: source_offset + call.end,
            arguments: split_function_arguments(&source[arguments_start..arguments_end]),
            namespace: call.namespace,
            local: call.local,
            display_name: call.display_name,
        });
    }
}

struct LexicalFunctionCall {
    start: usize,
    arguments_start: usize,
    end: usize,
    namespace: String,
    local: String,
    display_name: String,
}

fn first_namespaced_call(
    source: &str,
    namespaces: &[(String, String)],
    accepts: impl Fn(&str, &str) -> bool + Copy,
) -> Option<LexicalFunctionCall> {
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
        if !is_ncname_start(character) {
            cursor += character.len_utf8();
            continue;
        }
        let start = cursor;
        cursor += character.len_utf8();
        while cursor < source.len() {
            let next = source[cursor..].chars().next()?;
            if next != ':' && !is_ncname_char(next) {
                break;
            }
            cursor += next.len_utf8();
        }
        let lexical = &source[start..cursor];
        let Some((prefix, local)) = lexical.split_once(':') else {
            continue;
        };
        let Some(namespace) = namespaces
            .iter()
            .find_map(|(candidate, namespace)| (candidate == prefix).then_some(namespace))
        else {
            continue;
        };
        if !accepts(namespace, local) {
            continue;
        }
        let mut open = cursor;
        while open < source.len() && source[open..].chars().next().is_some_and(is_xpath_space) {
            open += source[open..].chars().next()?.len_utf8();
        }
        if !source[open..].starts_with('(') {
            continue;
        }
        let close = matching_parenthesis(source, open)?;
        return Some(LexicalFunctionCall {
            start,
            arguments_start: open + 1,
            end: close + 1,
            namespace: namespace.clone(),
            local: local.to_owned(),
            display_name: lexical.to_owned(),
        });
    }
    None
}

pub(crate) fn unprefixed_function_calls(source: &str, name: &str) -> Vec<FunctionCall> {
    let mut calls = Vec::new();
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
        if !is_ncname_start(character) {
            cursor += character.len_utf8();
            continue;
        }
        let start = cursor;
        cursor += character.len_utf8();
        while cursor < source.len() {
            let Some(next) = source[cursor..].chars().next() else {
                break;
            };
            if !is_ncname_char(next) {
                break;
            }
            cursor += next.len_utf8();
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
        let Some(close) = matching_parenthesis(source, open) else {
            continue;
        };
        calls.push(FunctionCall {
            start,
            end: close + 1,
            arguments: split_function_arguments(&source[open + 1..close]),
            namespace: String::new(),
            local: name.to_owned(),
            display_name: name.to_owned(),
        });
    }
    calls
}

fn is_xpath_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn matching_parenthesis(source: &str, open: usize) -> Option<usize> {
    let mut quote = None;
    let mut depth = 0usize;
    for (offset, character) in source[open..].char_indices() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
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
    use super::innermost_namespaced_call;

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
}
