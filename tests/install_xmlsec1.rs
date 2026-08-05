#![cfg(unix)]

//! Integration coverage for the pinned xmlsec1 installation workflow.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "xml-sec-install-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock must follow the Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("temporary test directory must be creatable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn tool(&self, name: &str, source: &str) {
        let path = self.path().join("tools").join(name);
        std::fs::write(&path, source).expect("fake tool must be writable");
        let mut permissions = std::fs::metadata(&path)
            .expect("fake tool metadata must be readable")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("fake tool must be executable");
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("temporary test directory must be removable");
    }
}

#[test]
fn failed_install_replacement_restores_previous_xmlsec() {
    // The staged directory move is the commit point. A failure there must
    // leave the previously working installation intact rather than letting
    // EXIT cleanup delete its backup.
    let root = TestDirectory::new();
    let tools = root.path().join("tools");
    let prefix = root.path().join("xmlsec-prefix");
    std::fs::create_dir_all(prefix.join("bin")).expect("old installation must be creatable");
    std::fs::create_dir_all(&tools).expect("fake tool directory must be creatable");
    std::fs::write(prefix.join("sentinel"), "previous installation")
        .expect("old installation sentinel must be writable");

    root.tool(
        "curl",
        "#!/bin/sh\nwhile [ \"$1\" != \"--output\" ]; do shift; done\n: > \"$2\"\n",
    );
    root.tool("sha256sum", "#!/bin/sh\nexit 0\n");
    root.tool(
        "tar",
        "#!/bin/sh\nwhile [ \"$1\" != \"--directory\" ]; do shift; done\nwork=$2\nsource=\"$work/xmlsec-5fdd47dc35753438bdc38b6e96c1a3805c67a483\"\nmkdir -p \"$source\"\nprintf '#!/bin/sh\\nexit 0\\n' > \"$source/autogen.sh\"\nchmod +x \"$source/autogen.sh\"\n",
    );
    root.tool("nproc", "#!/bin/sh\nprintf '1\\n'\n");
    root.tool(
        "make",
        "#!/bin/sh\nfor arg in \"$@\"; do\n  case \"$arg\" in DESTDIR=*) dest=${arg#DESTDIR=} ;; esac\ndone\nif [ -n \"${dest:-}\" ]; then\n  mkdir -p \"$dest$XMLSEC1_PREFIX/bin\"\n  printf '#!/bin/sh\\nexit 0\\n' > \"$dest$XMLSEC1_PREFIX/bin/xmlsec1\"\n  chmod +x \"$dest$XMLSEC1_PREFIX/bin/xmlsec1\"\nfi\n",
    );
    root.tool(
        "mv",
        "#!/bin/sh\ncount=0\n[ ! -f \"$MV_COUNT_FILE\" ] || count=$(cat \"$MV_COUNT_FILE\")\ncount=$((count + 1))\nprintf '%s\\n' \"$count\" > \"$MV_COUNT_FILE\"\n[ \"$count\" -ne 2 ] || exit 23\nexec /bin/mv \"$@\"\n",
    );

    let inherited_path = std::env::var_os("PATH").expect("test process must have PATH");
    let path =
        std::env::join_paths(std::iter::once(tools).chain(std::env::split_paths(&inherited_path)))
            .expect("test PATH must be joinable");
    let status = Command::new("bash")
        .arg("scripts/install-xmlsec1.sh")
        .env("XMLSEC1_PREFIX", &prefix)
        .env("MV_COUNT_FILE", root.path().join("mv-count"))
        .env("PATH", path)
        .status()
        .expect("installation script must run");

    assert!(
        !status.success(),
        "injected staged move failure must propagate"
    );
    assert_eq!(
        std::fs::read_to_string(prefix.join("sentinel"))
            .expect("previous installation must be restored"),
        "previous installation"
    );
}
