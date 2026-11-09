//! Links the system libxml2 and compiles the record of its structure layout.

fn main() {
    // pkg-config prints the link directives; the include paths it returns
    // compile the layout record against the very headers being linked.
    let library = pkg_config::Config::new()
        .probe("libxml-2.0")
        .expect("libxml2 and its pkg-config file (libxml-2.0) must be installed");
    let mut build = cc::Build::new();
    build.file("src/layout.c");
    for include in &library.include_paths {
        build.include(include);
        // Some distributions point at the parent of `libxml/`.
        build.include(include.join("libxml2"));
    }
    build.compile("xml_sec_libxml2_layout");
    println!("cargo::rerun-if-changed=src/layout.c");
}
