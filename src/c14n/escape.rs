//! Text and attribute value escaping for canonical XML.

use std::io::{self, Write};

/// Escape text node content for canonical XML.
///
/// Replaces: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `\r` → `&#xD;`
pub(crate) fn escape_text(s: &str, output: &mut impl Write) -> io::Result<()> {
    for b in s.bytes() {
        match b {
            b'&' => output.write_all(b"&amp;")?,
            b'<' => output.write_all(b"&lt;")?,
            b'>' => output.write_all(b"&gt;")?,
            b'\r' => output.write_all(b"&#xD;")?,
            _ => output.write_all(&[b])?,
        }
    }
    Ok(())
}

/// Escape attribute value for canonical XML.
///
/// Replaces: `&` → `&amp;`, `<` → `&lt;`, `"` → `&quot;`,
/// `\t` → `&#x9;`, `\n` → `&#xA;`, `\r` → `&#xD;`
pub(crate) fn escape_attr(s: &str, output: &mut impl Write) -> io::Result<()> {
    for b in s.bytes() {
        match b {
            b'&' => output.write_all(b"&amp;")?,
            b'<' => output.write_all(b"&lt;")?,
            b'"' => output.write_all(b"&quot;")?,
            b'\t' => output.write_all(b"&#x9;")?,
            b'\n' => output.write_all(b"&#xA;")?,
            b'\r' => output.write_all(b"&#xD;")?,
            _ => output.write_all(&[b])?,
        }
    }
    Ok(())
}

/// Escape only carriage returns in comment/PI content for canonical XML.
///
/// C14N spec section 2.3: `\r` in comments and PIs → `&#xD;`
pub(crate) fn escape_cr(s: &str, output: &mut impl Write) -> io::Result<()> {
    for b in s.bytes() {
        match b {
            b'\r' => output.write_all(b"&#xD;")?,
            _ => output.write_all(&[b])?,
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn text_escaping() {
        let mut out = Vec::new();
        escape_text("a < b & c > d\r\n", &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).expect("valid utf8"),
            "a &lt; b &amp; c &gt; d&#xD;\n"
        );
    }

    #[test]
    fn attr_escaping() {
        let mut out = Vec::new();
        escape_attr("he said \"hi\" & \t\n\r", &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).expect("valid utf8"),
            "he said &quot;hi&quot; &amp; &#x9;&#xA;&#xD;"
        );
    }

    #[test]
    fn passthrough_plain_text() {
        let mut out = Vec::new();
        escape_text("hello world", &mut out).unwrap();
        assert_eq!(String::from_utf8(out).expect("valid utf8"), "hello world");
    }
}
