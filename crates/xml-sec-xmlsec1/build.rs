//! Compiles the C half of the boundary (libxml2's allocator, which may be a
//! macro, and the record of the xmlsec1 structure layouts) against the
//! crate's own headers, with the defines a consumer gets from the
//! pkg-config file.

use std::path::Path;

/// The `-D` flags of the pkg-config template's `Cflags:` line.
fn defines(template: &str) -> Vec<(String, String)> {
    let cflags = template
        .lines()
        .find_map(|line| line.strip_prefix("Cflags:"))
        .expect("xml-sec-xmlsec1.pc.in has a Cflags line");
    cflags
        .split_whitespace()
        .filter_map(|flag| flag.strip_prefix("-D"))
        .map(|define| match define.split_once('=') {
            Some((name, value)) => (name.to_owned(), value.to_owned()),
            None => (define.to_owned(), "1".to_owned()),
        })
        .collect()
}

fn main() {
    let template =
        std::fs::read_to_string("xml-sec-xmlsec1.pc.in").expect("read the pkg-config template");
    // xml-sec-libxml2 links libxml2; this probe only finds its headers.
    let libxml2 = pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("libxml-2.0")
        .expect("libxml2 and its pkg-config file (libxml-2.0) must be installed");
    let mut build = cc::Build::new();
    build.file("src/shim.c").file("src/layout.c");
    build.include(Path::new("include"));
    for include in &libxml2.include_paths {
        build.include(include);
        // Some distributions point at the parent of `libxml/`.
        build.include(include.join("libxml2"));
    }
    for (name, value) in defines(&template) {
        build.define(&name, Some(value.as_str()));
    }
    build.compile("xml_sec_xmlsec1_c");
    println!("cargo::rerun-if-changed=xml-sec-xmlsec1.pc.in");
    println!("cargo::rerun-if-changed=src/shim.c");
    println!("cargo::rerun-if-changed=src/layout.c");
    println!("cargo::rerun-if-changed=include");
}
