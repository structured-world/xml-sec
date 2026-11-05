use super::LedgerEntry;
use super::layout::{Body, Member, enum_members, parse_output, probe_source, struct_members};
use super::ownership::{Rules, classify, signature};
use super::symbols::{Export, Kind, library};
use std::collections::{BTreeMap, BTreeSet};

fn names(members: &[Member]) -> Vec<&str> {
    members
        .iter()
        .map(|member| match member {
            Member::Name(name) | Member::Directive(name) => name.as_str(),
        })
        .collect()
}

/// Every declarator form the public structs use yields its member, and a
/// conditional member keeps its directives so the probe sees the configured set.
#[test]
fn struct_members_follow_declarators_and_directives() {
    let header = "struct _Other { int x; };\n\
        struct _Sample {\n\
            void* userData; /**< comment; with a semicolon */\n\
            int (*callback)(int a, int b);\n\
            xmlSecByte data[16];\n\
            unsigned int first, second;\n\
        #ifndef XMLSEC_NO_X509\n\
            time_t when;\n\
        #endif /* XMLSEC_NO_X509 */\n\
        };\n";
    let members = struct_members(header, "_Sample").expect("parse");
    assert_eq!(
        names(&members),
        [
            "userData",
            "callback",
            "data",
            "first",
            "second",
            "#ifndef XMLSEC_NO_X509",
            "when",
            "#endif",
        ]
    );
    assert!(matches!(members[5], Member::Directive(_)));
}

/// A missing struct, a nested definition and a member without a terminator
/// are errors, not an empty or partial layout.
#[test]
fn struct_members_refuse_what_they_cannot_measure() {
    let missing = struct_members("struct _A { int a; };", "_B").expect_err("missing");
    assert!(missing.contains("no definition of struct _B"), "{missing}");
    let nested =
        struct_members("struct _A { struct { int b; } inner; };", "_A").expect_err("nested");
    assert!(nested.contains("nested definitions"), "{nested}");
    let open = struct_members("struct _A { int a; int b };", "_A").expect_err("open");
    assert!(open.contains("member without a terminator"), "{open}");
}

/// Enumerators with and without values, and a last one without a comma.
#[test]
fn enum_members_read_every_enumerator() {
    let header = "typedef enum { ignored } Other;\n\
        typedef enum {\n\
            xmlSecFirst = 0, /* comment, with a comma */\n\
            xmlSecSecond,\n\
        #ifndef XMLSEC_NO_X\n\
            xmlSecThird = (1 << 2)\n\
        #endif\n\
        } xmlSecSample;\n";
    let members = enum_members(header, "xmlSecSample").expect("parse");
    assert_eq!(
        names(&members),
        [
            "xmlSecFirst",
            "xmlSecSecond",
            "#ifndef XMLSEC_NO_X",
            "xmlSecThird",
            "#endif"
        ]
    );
    let missing = enum_members(header, "xmlSecAbsent").expect_err("missing");
    assert!(
        missing.contains("no definition of enum xmlSecAbsent"),
        "{missing}"
    );
}

fn body(name: &str, members: &[&str]) -> Body {
    Body {
        name: name.to_owned(),
        members: members
            .iter()
            .map(|member| Member::Name((*member).to_owned()))
            .collect(),
    }
}

const MODEL: &str = "D pointer 8\nD long 8\nD size_t 8\nD time_t 8\n";

/// The probe's lines become the layout in declaration order.
#[test]
fn probe_output_becomes_layouts_and_values() {
    let structs = [body("_S", &["a", "b"])];
    let enums = [body("E", &["One", "Two"])];
    let output = format!("{MODEL}S _S 16 8\nF _S a 0 4\nF _S b 8 8\nE E One 0\nE E Two -1\n");
    let probe = parse_output(&output, &structs, &enums).expect("parse");
    let json =
        serde_json::to_value((&probe.structs, &probe.enums, &probe.data_model)).expect("serialize");
    assert_eq!(
        json,
        serde_json::json!([
            [{"name": "_S", "size": 16, "align": 8, "fields": [
                {"name": "a", "offset": 0, "size": 4},
                {"name": "b", "offset": 8, "size": 8}
            ]}],
            [{"name": "E", "values": [{"name": "One", "value": 0}, {"name": "Two", "value": -1}]}],
            {"pointer": 8, "long": 8, "size_t": 8, "time_t": 8}
        ])
    );
}

/// A struct the probe did not measure, an unknown line, a field before its
/// struct and a missing data-model size each fail.
#[test]
fn probe_output_must_be_complete_and_known() {
    let structs = [body("_S", &["a"])];
    let missing = parse_output(MODEL, &structs, &[])
        .err()
        .expect("missing struct");
    assert!(missing.contains("did not measure struct _S"), "{missing}");
    let unknown = parse_output(&format!("{MODEL}X y\n"), &[], &[])
        .err()
        .expect("unknown");
    assert!(
        unknown.contains("unexpected probe output line"),
        "{unknown}"
    );
    let early = parse_output(&format!("{MODEL}F _S a 0 4\n"), &structs, &[])
        .err()
        .expect("early field");
    assert!(early.contains("before its struct"), "{early}");
    let model = parse_output("D pointer 8\n", &[], &[])
        .err()
        .expect("model");
    assert!(model.contains("sizeof long"), "{model}");
}

/// The probe repeats directives verbatim and measures every named member.
#[test]
fn probe_source_measures_every_member() {
    let structs = [Body {
        name: "_S".to_owned(),
        members: vec![
            Member::Name("a".to_owned()),
            Member::Directive("#ifndef XMLSEC_NO_X".to_owned()),
            Member::Name("b".to_owned()),
            Member::Directive("#endif".to_owned()),
        ],
    }];
    let source = probe_source(&["xmlsec.h".to_owned()], &structs, &[body("E", &["One"])]);
    assert!(source.starts_with("/* Generated"));
    assert!(source.contains("#define XMLSEC_PRIVATE 1\n"));
    assert!(source.contains("#include <xmlsec/xmlsec.h>\n"));
    assert!(source.contains(
        "LAYOUT_STRUCT(_S);\nLAYOUT_FIELD(_S, a);\n#ifndef XMLSEC_NO_X\nLAYOUT_FIELD(_S, b);\n#endif\n"
    ));
    assert!(source.contains("LAYOUT_VALUE(E, One);\n"));
}

fn export(name: &str, kind: Kind) -> Export {
    Export {
        name: name.to_owned(),
        kind,
        size: (kind == Kind::Data).then_some(8),
    }
}

/// Own exports are listed with their declaration or none; foreign ones only
/// counted, with a digest independent of their order.
#[test]
fn symbols_split_own_and_foreign_exports() {
    let declared = BTreeMap::from([("xmlSecDeclared", "export-function")]);
    let first = library(
        "libxmlsec1",
        vec![
            export("xmlSecInternal", Kind::Function),
            export("OPENSSL_free", Kind::Function),
            export("xmlSecDeclared", Kind::Function),
            export("BIO_new", Kind::Function),
        ],
        &declared,
    )
    .expect("library");
    let json = serde_json::to_value(&first).expect("serialize");
    assert_eq!(json["symbols"][0]["name"], "xmlSecDeclared");
    assert_eq!(json["symbols"][0]["declaration"], "export-function");
    assert_eq!(json["symbols"][1]["name"], "xmlSecInternal");
    assert!(json["symbols"][1].get("declaration").is_none());
    assert_eq!(json["foreign"]["count"], 2);
    let reordered = library(
        "libxmlsec1",
        vec![
            export("BIO_new", Kind::Function),
            export("OPENSSL_free", Kind::Function),
        ],
        &declared,
    )
    .expect("library");
    let other = serde_json::to_value(&reordered).expect("serialize");
    assert_eq!(json["foreign"]["sha256"], other["foreign"]["sha256"]);

    let duplicate = library(
        "libxmlsec1",
        vec![
            export("xmlSecA", Kind::Function),
            export("xmlSecA", Kind::Data),
        ],
        &declared,
    )
    .err()
    .expect("duplicate");
    assert!(
        duplicate.contains("xmlSecA is exported twice"),
        "{duplicate}"
    );
}

/// The return type, parameter names and pointer parameters of a declaration.
#[test]
fn signatures_split_return_type_and_parameters() {
    let pointers = BTreeSet::from(["xmlSecKeyDataId".to_owned()]);
    let parsed = signature(
        "xmlSecKeyAdoptData",
        "XMLSEC_EXPORT int xmlSecKeyAdoptData (xmlSecKeyPtr key, xmlSecKeyDataId id, int (*cb)(void* a, int b), const xmlChar* names[], int count);",
        &pointers,
    )
    .expect("signature");
    assert_eq!(parsed.return_type, "int");
    let parameters: Vec<(&str, bool)> = parsed
        .parameters
        .iter()
        .map(|parameter| (parameter.name.as_str(), parameter.pointer))
        .collect();
    assert_eq!(
        parameters,
        [
            ("key", true),
            ("id", true),
            ("cb", true),
            ("names", true),
            ("count", false)
        ]
    );
    let none = signature(
        "xmlSecKeyCreate",
        "XMLSEC_EXPORT xmlSecKeyPtr xmlSecKeyCreate (void);",
        &pointers,
    )
    .expect("signature");
    assert_eq!(none.return_type, "xmlSecKeyPtr");
    assert!(none.parameters.is_empty());
}

fn entry(kind: &str, name: &str, detail: &str) -> LedgerEntry {
    LedgerEntry {
        kind: kind.to_owned(),
        name: name.to_owned(),
        source: "include/xmlsec/keys.h".to_owned(),
        detail: detail.to_owned(),
    }
}

fn ledger() -> Vec<LedgerEntry> {
    vec![
        entry(
            "typedef",
            "xmlSecKeyPtr",
            "typedef struct _xmlSecKey xmlSecKey, *xmlSecKeyPtr;",
        ),
        entry(
            "export-function",
            "xmlSecKeyCreate",
            "XMLSEC_EXPORT xmlSecKeyPtr xmlSecKeyCreate (void);",
        ),
        entry(
            "export-function",
            "xmlSecKeyDestroy",
            "XMLSEC_EXPORT void xmlSecKeyDestroy (xmlSecKeyPtr key);",
        ),
        entry(
            "export-function",
            "xmlSecKeyGetName",
            "XMLSEC_EXPORT const xmlChar* xmlSecKeyGetName (xmlSecKeyPtr key);",
        ),
        entry(
            "export-function",
            "xmlSecKeyAdoptName",
            "XMLSEC_EXPORT int xmlSecKeyAdoptName (xmlSecKeyPtr key, xmlChar* name);",
        ),
        entry(
            "export-function",
            "xmlSecKeyWrite",
            "XMLSEC_EXPORT int xmlSecKeyWrite (xmlSecKeyPtr key, xmlSecByte** buf, const xmlChar** names);",
        ),
    ]
}

fn exported(ledger: &[LedgerEntry]) -> Vec<super::symbols::Library> {
    let declared: BTreeMap<&str, &str> = ledger
        .iter()
        .filter(|item| item.kind == "export-function")
        .map(|item| (item.name.as_str(), "export-function"))
        .collect();
    let exports = declared
        .keys()
        .map(|name| export(name, Kind::Function))
        .collect();
    vec![library("libxmlsec1", exports, &declared).expect("library")]
}

fn rules(json: serde_json::Value) -> Rules {
    serde_json::from_value(json).expect("rules")
}

fn base_rules() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "external_releases": ["xmlFree"],
        "returns": [
            {"id": "create", "name_regex": "Create$", "returns": {"kind": "owned", "release": "{type}Destroy"}, "rationale": "constructors"},
            {"id": "getter", "name_regex": "Get", "returns": {"kind": "borrowed", "owner": "$first"}, "rationale": "getters"}
        ],
        "outputs": [
            {"id": "written", "names": ["xmlSecKeyWrite"], "parameter": "buf", "gives": {"kind": "owned", "release": "xmlFree"}, "rationale": "writers"}
        ],
        "adopts": [
            {"id": "adopt", "name_regex": "Adopt", "parameters": ["$last-pointer"], "rationale": "adopters"}
        ]
    })
}

/// Rules resolve placeholders: the destroy function from the returned type,
/// the owner from the first parameter, the adopted argument by position.
#[test]
fn ownership_rules_resolve_per_function() {
    let ledger = ledger();
    let functions = classify(&rules(base_rules()), &ledger, &exported(&ledger)).expect("classify");
    let json = serde_json::to_value(&functions).expect("serialize");
    assert_eq!(
        json,
        serde_json::json!([
            {"name": "xmlSecKeyAdoptName", "returns": {"kind": "value"}, "adopts": ["name"]},
            {"name": "xmlSecKeyCreate", "returns": {"kind": "owned", "release": "xmlSecKeyDestroy"}},
            {"name": "xmlSecKeyDestroy", "returns": {"kind": "value"}},
            {"name": "xmlSecKeyGetName", "returns": {"kind": "borrowed", "owner": "key"}},
            {"name": "xmlSecKeyWrite", "returns": {"kind": "value"}, "outputs": {"buf": {"kind": "owned", "release": "xmlFree"}}}
        ])
    );
}

/// A writable pointer-to-pointer parameter needs a rule; a const one is input.
#[test]
fn ownership_requires_a_rule_for_every_output_parameter() {
    let ledger = ledger();
    let mut json = base_rules();
    json["outputs"] = serde_json::json!([]);
    let error = classify(&rules(json), &ledger, &exported(&ledger))
        .err()
        .expect("unclassified output");
    assert!(error.contains("xmlSecKeyWrite (output buf)"), "{error}");
    assert!(!error.contains("output names"), "{error}");
}

/// A pointer-returning function no rule covers fails generation by name.
#[test]
fn ownership_requires_a_rule_for_every_returned_pointer() {
    let ledger = ledger();
    let mut json = base_rules();
    json["returns"].as_array_mut().expect("array").remove(1);
    let error = classify(&rules(json), &ledger, &exported(&ledger))
        .err()
        .expect("unclassified");
    assert!(error.contains("xmlSecKeyGetName"), "{error}");
}

/// A rule that matches nothing, a release that is not exported and a rule
/// without a rationale are each refused.
#[test]
fn ownership_rules_must_be_live_and_resolvable() {
    let ledger = ledger();
    let mut stale = base_rules();
    stale["adopts"][0]["name_regex"] = "NoSuchFunction".into();
    let error = classify(&rules(stale), &ledger, &exported(&ledger))
        .err()
        .expect("stale");
    assert!(error.contains("match nothing: adopt"), "{error}");

    let mut release = base_rules();
    release["returns"][0]["returns"]["release"] = "xmlSecKeyFree".into();
    let error = classify(&rules(release), &ledger, &exported(&ledger))
        .err()
        .expect("release");
    assert!(
        error.contains("released by xmlSecKeyFree, which is not exported"),
        "{error}"
    );

    let mut silent = base_rules();
    silent["returns"][1]["rationale"] = " ".into();
    let error = classify(&rules(silent), &ledger, &exported(&ledger))
        .err()
        .expect("rationale");
    assert!(error.contains("getter gives no rationale"), "{error}");
}

/// A function the libraries do not export is outside the baseline even if
/// the ledger declares it.
#[test]
fn ownership_covers_only_exported_functions() {
    let ledger = ledger();
    let mut libraries = exported(&ledger);
    libraries[0] = library(
        "libxmlsec1",
        vec![export("xmlSecKeyDestroy", Kind::Function)],
        &BTreeMap::from([("xmlSecKeyDestroy", "export-function")]),
    )
    .expect("library");
    let mut json = base_rules();
    json["returns"] = serde_json::json!([]);
    json["outputs"] = serde_json::json!([]);
    json["adopts"] = serde_json::json!([]);
    let functions = classify(&rules(json), &ledger, &libraries).expect("classify");
    let json = serde_json::to_value(&functions).expect("serialize");
    assert_eq!(
        json,
        serde_json::json!([{"name": "xmlSecKeyDestroy", "returns": {"kind": "value"}}])
    );
}
