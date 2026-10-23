#!/usr/bin/env python3
"""Archive corpus plus its source overlay; exclude tool caches and build outputs."""
import argparse
import gzip
import hashlib
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "interop/xades"
SOURCES = ["LICENSE", "LICENSE-THIRD-PARTY", "README.md", "interop/.gitignore", "scripts/generate-xades-fixtures.sh",
           "scripts/xades-interop.py", "scripts/xades-dss.py", "scripts/test-xades-interop.py",
           "scripts/investigate-xades-dss.py",
           "scripts/package-xades-interop.py", "crates/xml-sec-xades/examples/interop_probe.rs"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("output", type=Path)
    output = parser.parse_args().output.resolve()
    if output.exists() or output.is_relative_to(PACKAGE):
        raise SystemExit("choose a new archive path outside the corpus")
    files = [ROOT / name for name in SOURCES]
    files += sorted(p for p in PACKAGE.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    if any(p.is_symlink() or set(p.relative_to(ROOT).parts) & {"target", ".tools", "__pycache__"} for p in files):
        raise SystemExit("unexpected link or build output in corpus")
    checksums = PACKAGE / "SHA256SUMS"
    checksums.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT)}\n" for p in files))
    def portable(info):
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        return info

    with output.open("wb") as destination, gzip.GzipFile(filename="", fileobj=destination, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for path in files + [checksums]:
                archive.add(path, arcname=str(path.relative_to(ROOT)), filter=portable)
    # Check archive content and inventory, not just creation's exit status.
    with tarfile.open(output) as archive:
        for line in checksums.read_text().splitlines():
            expected, path = line.split("  ", 1)
            if hashlib.sha256(archive.extractfile(path).read()).hexdigest() != expected:
                raise SystemExit(f"archive hash mismatch: {path}")
    print(f"{output}\nSHA256 {hashlib.sha256(output.read_bytes()).hexdigest()}\n{len(files)} inventoried files")
