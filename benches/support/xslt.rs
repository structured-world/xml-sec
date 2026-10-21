use std::sync::Arc;
use xml_sec_xslt::{
    CompileBudget, Compiler, Document, ExecutionBudget, ExecutionEnvironment, ExecutionOptions,
    NoResolver, Parameters, Stylesheet,
};

pub const PHASES: [&str; 5] = ["compile", "tree", "serialize", "retained", "end_to_end"];

pub struct Fixture {
    pub source: String,
    pub stylesheet: String,
    pub expected: Vec<u8>,
    resolver: Arc<NoResolver>,
}

impl Fixture {
    pub fn new(shape: &str, size: usize) -> Self {
        assert!([16, 256].contains(&size));
        let (body, input, output) = match shape {
            "items" => (
                "<xsl:for-each select='root/item'><v><xsl:value-of select='.'/></v></xsl:for-each>"
                    .to_owned(),
                "<item>payload</item>".repeat(size),
                "<v>payload</v>".repeat(size),
            ),
            "amplification" => (
                format!(
                    "<xsl:call-template name='expand'><xsl:with-param name='n' select='{depth}'/></xsl:call-template>",
                    depth = if size == 16 { 6 } else { 10 }
                ),
                String::new(),
                "<v>payload</v>".repeat(if size == 16 { 64 } else { 1024 }),
            ),
            _ => panic!("unknown XSLT fixture"),
        };
        let templates = (0..size)
            .map(|n| format!("<xsl:template name='unused{n}'/>"))
            .collect::<String>();
        Self {
            source: format!("<root>{input}</root>"),
            stylesheet: format!(
                "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:output omit-xml-declaration='yes'/><xsl:template match='/'><out>{body}</out></xsl:template><xsl:template name='expand'><xsl:param name='n'/><xsl:choose><xsl:when test='$n &gt; 0'><xsl:call-template name='expand'><xsl:with-param name='n' select='$n - 1'/></xsl:call-template><xsl:call-template name='expand'><xsl:with-param name='n' select='$n - 1'/></xsl:call-template></xsl:when><xsl:otherwise><v>payload</v></xsl:otherwise></xsl:choose></xsl:template>{templates}</xsl:stylesheet>"
            ),
            expected: format!("<out>{output}</out>\n").into_bytes(),
            resolver: Arc::new(NoResolver),
        }
    }

    pub fn compile(&self) -> Stylesheet {
        Compiler::new(
            Arc::clone(&self.resolver),
            CompileBudget::new(1 << 20, 0, 128, 64 << 20),
        )
        .compile(&self.stylesheet, Some("urn:benchmark:stylesheet"))
        .expect("compile benchmark stylesheet")
    }

    pub fn parse(&self) -> Document {
        Document::parse(&self.source, Some("urn:benchmark:source")).expect("benchmark source")
    }

    pub fn execute(&self, sheet: &Stylesheet, source: &Document) -> xml_sec_xslt::TransformResult {
        sheet
            .execute(
                source,
                &Parameters::default(),
                Arc::clone(&self.resolver),
                options(),
            )
            .expect("transform")
    }

    pub fn tree<'a>(
        &self,
        sheet: &'a Stylesheet,
        source: &Document,
    ) -> xml_sec_xslt::MeasuredTree<'a> {
        sheet
            .measure_tree(
                source,
                &Parameters::default(),
                ExecutionEnvironment::new(Arc::clone(&self.resolver)),
                options(),
            )
            .expect("result tree")
    }
}

pub fn options() -> ExecutionOptions {
    ExecutionOptions {
        budget: ExecutionBudget {
            source_bytes: 1 << 20,
            external_documents: 0,
            recursion_depth: 128,
            xpath_evaluations: 1_000_000,
            xpath_operations: 10_000_000,
            extension_operations: 0,
            pattern_evaluations: 1_000_000,
            template_applications: 100_000,
            sort_comparisons: 1_000_000,
            key_entries: 100_000,
            result_nodes: 100_000,
            serialized_bytes: 8 << 20,
            messages: 0,
            owned_bytes: 64 << 20,
        },
        initial_mode: None,
        initial_template: None,
    }
}
