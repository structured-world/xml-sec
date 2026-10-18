use super::lexical::{is_ncname_char, is_ncname_start, is_xml_whitespace, trim_xml_whitespace};
use super::{
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

#[cfg(all(test, not(feature = "embedded")))]
mod tests;
