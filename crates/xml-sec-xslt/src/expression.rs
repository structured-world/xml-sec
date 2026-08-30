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
        if !is_name_start(character) {
            cursor += character.len_utf8();
            continue;
        }
        let start = cursor;
        cursor += character.len_utf8();
        while cursor < source.len() {
            let next = source[cursor..].chars().next()?;
            if !is_name_character(next) {
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
        while open < source.len()
            && source[open..]
                .chars()
                .next()
                .is_some_and(char::is_whitespace)
        {
            open += source[open..].chars().next()?.len_utf8();
        }
        if !source[open..].starts_with('(') {
            continue;
        }
        let close = matching_parenthesis(source, open)?;
        let arguments_source = &source[open + 1..close];
        if let Some(mut nested) = innermost_namespaced_call(arguments_source, namespaces, accepts) {
            nested.start += open + 1;
            nested.end += open + 1;
            return Some(nested);
        }
        return Some(FunctionCall {
            start,
            end: close + 1,
            arguments: split_function_arguments(arguments_source),
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
        if !is_name_start(character) {
            cursor += character.len_utf8();
            continue;
        }
        let start = cursor;
        cursor += character.len_utf8();
        while cursor < source.len() {
            let Some(next) = source[cursor..].chars().next() else {
                break;
            };
            if !is_name_character(next) {
                break;
            }
            cursor += next.len_utf8();
        }
        if &source[start..cursor] != name {
            continue;
        }
        let mut open = cursor;
        while open < source.len()
            && source[open..]
                .chars()
                .next()
                .is_some_and(char::is_whitespace)
        {
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

fn is_name_start(character: char) -> bool {
    character.is_alphabetic() || character == '_'
}

fn is_name_character(character: char) -> bool {
    is_name_start(character) || character.is_ascii_digit() || matches!(character, '-' | '.' | ':')
}
