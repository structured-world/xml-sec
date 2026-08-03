//! Text and attribute value escaping for canonical XML.

use std::io::{self, Write};

/// Escape text node content for canonical XML.
///
/// Replaces: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `\r` → `&#xD;`
pub(crate) fn escape_text(s: &str, output: &mut impl Write) -> io::Result<()> {
    escape_runs(s, output, |byte| match byte {
        b'&' => Some(b"&amp;"),
        b'<' => Some(b"&lt;"),
        b'>' => Some(b"&gt;"),
        b'\r' => Some(b"&#xD;"),
        _ => None,
    })
}

/// Escape attribute value for canonical XML.
///
/// Replaces: `&` → `&amp;`, `<` → `&lt;`, `"` → `&quot;`,
/// `\t` → `&#x9;`, `\n` → `&#xA;`, `\r` → `&#xD;`
pub(crate) fn escape_attr(s: &str, output: &mut impl Write) -> io::Result<()> {
    escape_runs(s, output, |byte| match byte {
        b'&' => Some(b"&amp;"),
        b'<' => Some(b"&lt;"),
        b'"' => Some(b"&quot;"),
        b'\t' => Some(b"&#x9;"),
        b'\n' => Some(b"&#xA;"),
        b'\r' => Some(b"&#xD;"),
        _ => None,
    })
}

/// Escape only carriage returns in comment/PI content for canonical XML.
///
/// C14N spec section 2.3: `\r` in comments and PIs → `&#xD;`
pub(crate) fn escape_cr(s: &str, output: &mut impl Write) -> io::Result<()> {
    escape_runs(s, output, |byte| {
        (byte == b'\r').then_some(b"&#xD;" as &'static [u8])
    })
}

fn escape_runs(
    source: &str,
    output: &mut impl Write,
    replacement: impl Fn(u8) -> Option<&'static [u8]>,
) -> io::Result<()> {
    let bytes = source.as_bytes();
    let mut run_start = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if let Some(escaped) = replacement(byte) {
            if run_start < index {
                output.write_all(&bytes[run_start..index])?;
            }
            output.write_all(escaped)?;
            run_start = index + 1;
        }
    }
    if run_start < bytes.len() {
        output.write_all(&bytes[run_start..])?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CountingWriter {
        bytes: Vec<u8>,
        writes: usize,
    }

    impl Write for CountingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

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

    #[test]
    fn escapers_batch_contiguous_utf8_runs() {
        // Bounds-checking writers must see one call per unchanged run, not one
        // per UTF-8 byte, while escaped ASCII remains a separate write.
        let mut text = CountingWriter::default();
        escape_text("alphaα&betaβ", &mut text).unwrap();
        assert_eq!(text.writes, 3);
        assert_eq!(text.bytes, "alphaα&amp;betaβ".as_bytes());

        let mut attribute = CountingWriter::default();
        escape_attr("alphaα\"betaβ", &mut attribute).unwrap();
        assert_eq!(attribute.writes, 3);
        assert_eq!(attribute.bytes, "alphaα&quot;betaβ".as_bytes());

        let mut carriage_return = CountingWriter::default();
        escape_cr("alphaα\rbetaβ", &mut carriage_return).unwrap();
        assert_eq!(carriage_return.writes, 3);
        assert_eq!(carriage_return.bytes, "alphaα&#xD;betaβ".as_bytes());
    }
}
