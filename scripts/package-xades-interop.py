#!/usr/bin/env python3
"""Archive corpus plus its source overlay; exclude tool caches and build outputs."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "interop/xades"
CASES = json.loads((PACKAGE / 'cases.json').read_text())
CORE_CASES = {case['name'] for case in CASES}
FIXTURES = {case['file'] for case in CASES} | {
    'fixtures/enveloped-control.template.xml', 'fixtures/signer.key', 'fixtures/signer.pem',
    'fixtures/intermediate.pem', 'fixtures/baseline/root.der', 'fixtures/baseline/signer.der',
    'fixtures/baseline/intermediate.der',
}
MINIMAL_CASES = {case['name'] for case in json.loads((PACKAGE / 'dss-investigation/expectations.json').read_text())['cases']}
SOURCES = ["LICENSE", "LICENSE-THIRD-PARTY", "README.md", "interop/.gitignore", "scripts/generate-xades-fixtures.sh",
           "scripts/xades-interop.py", "scripts/xades-dss.py", "scripts/test-xades-interop.py",
           "scripts/check-xades-interop.py", ".github/workflows/ci.yml",
           "scripts/investigate-xades-dss.py",
           "scripts/package-xades-interop.py", "crates/xml-sec-xades/examples/interop_probe.rs"]


def include_evidence(path):
    """Allow only corpus inputs, independent goldens and their maintained sources."""
    relative = path.relative_to(PACKAGE)
    parts = relative.parts
    if parts[0] == 'fixtures':
        return relative.as_posix() in FIXTURES
    if len(parts) == 3 and parts[0] in {'results', 'dss-investigation'}:
        names = MINIMAL_CASES if parts[0] == 'dss-investigation' else CORE_CASES
        if parts[1] not in names:
            return False
        if re.fullmatch(r'expected-(reference-\d+|signedinfo)\.bin', path.name):
            return True
        if parts[0] == 'dss-investigation' and path.name in {'signed.xml', 'template.xml'}:
            return True
    return relative.as_posix() in {
        '.gitattributes', 'README.md', 'PROVENANCE.md', 'COMMENT-DRAFT.md', 'SHA256SUMS', 'cases.json',
        'dss/pom.xml', 'dss/src/main/java/Probe.java', 'dss/src/main/java/BindingProbe.java',
        'dss-evidence/expectations.json', 'dss-investigation/README.md',
        'dss-investigation/expectations.json', 'dss-investigation/strict-policy-expectations.json',
        'dss-investigation/source-audit.json',
    }


def corpus_files():
    return sorted(p for p in PACKAGE.rglob('*') if p.is_file() and p.name != 'SHA256SUMS' and include_evidence(p))


def inventory(files):
    return ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT)}\n' for p in files)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("output", type=Path, nargs='?')
    parser.add_argument('--refresh-inventory', action='store_true', help='explicitly update the corpus asset inventory')
    options = parser.parse_args()
    if options.refresh_inventory:
        if options.output:
            parser.error('refresh inventory separately from packaging')
        (PACKAGE / 'SHA256SUMS').write_text(inventory(corpus_files()))
        raise SystemExit(0)
    if options.output is None:
        parser.error('archive output is required')
    output = options.output.resolve()
    if output.exists() or output.is_relative_to(PACKAGE):
        raise SystemExit("choose a new archive path outside the corpus")
    files = [ROOT / name for name in SOURCES]
    files += corpus_files()
    if any(p.is_symlink() or set(p.relative_to(ROOT).parts) & {"target", ".tools", "__pycache__"} for p in files):
        raise SystemExit("unexpected link or build output in corpus")
    checksums = PACKAGE / "SHA256SUMS"
    if checksums.read_text() != inventory(corpus_files()):
        raise SystemExit('stale corpus inventory; refresh explicitly before packaging')
    archive_inventory = inventory(files + [checksums])
    def portable(info):
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        return info

    with output.open("wb") as destination, gzip.GzipFile(filename="", fileobj=destination, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for path in files + [checksums]:
                archive.add(path, arcname=str(path.relative_to(ROOT)), filter=portable)
            info = tarfile.TarInfo('SHA256SUMS')
            data = archive_inventory.encode()
            info.size = len(data)
            archive.addfile(portable(info), io.BytesIO(data))
    # Check archive content and inventory, not just creation's exit status.
    with tarfile.open(output) as archive:
        for line in archive_inventory.splitlines():
            expected, path = line.split("  ", 1)
            if hashlib.sha256(archive.extractfile(path).read()).hexdigest() != expected:
                raise SystemExit(f"archive hash mismatch: {path}")
    print(f"{output}\nSHA256 {hashlib.sha256(output.read_bytes()).hexdigest()}\n{len(files)} inventoried files")
