#!/usr/bin/env python3
"""Mandatory live corpus check; all actual outputs stay in a fresh run directory."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'interop/xades'


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_goldens(expected, actual):
    """Every independently captured octet vector must be consumed, including empties."""
    expected_files = {p.relative_to(expected) for p in expected.rglob('expected-*.bin')}
    actual_files = {p.relative_to(actual) for p in actual.rglob('expected-*.bin')}
    if not expected_files or expected_files != actual_files:
        raise SystemExit(f'golden inventory mismatch: missing={expected_files-actual_files}, extra={actual_files-expected_files}')
    corpus = load('xades-interop')
    comparisons = []
    for path in sorted(expected_files):
        result = corpus.compare((expected / path).read_bytes(), (actual / path).read_bytes())
        comparisons.append(dict(file=str(path), **result))
        if result['status'] != 'verified':
            (actual / 'golden-comparison.json').write_text(json.dumps(comparisons, indent=2, ensure_ascii=False)+'\n')
            raise SystemExit(f'golden mismatch: {path}: {json.dumps(result)}')
    (actual / 'golden-comparison.json').write_text(json.dumps(comparisons, indent=2, ensure_ascii=False)+'\n')
    return len(expected_files)


def check_expectations(expected, actual):
    if json.loads(expected.read_text()) != json.loads(actual.read_text()):
        raise SystemExit(f'DSS expectation mismatch: {expected}; inspect {actual}')


def check_inventory():
    """Reject unreviewed assets and stale corpus hashes, independently of packaging."""
    package = load('package-xades-interop')
    tracked = subprocess.check_output(['git', 'ls-files', '-z', 'interop/xades'], cwd=ROOT).decode().split('\0')
    for path in filter(None, tracked):
        if not package.include_evidence(ROOT / path):
            raise SystemExit(f'run artifact or undeclared corpus file tracked by Git: {path}')
    inventory = {}
    for line in (PACKAGE / 'SHA256SUMS').read_text().splitlines():
        expected, path = line.split('  ', 1)
        if path in inventory:
            raise SystemExit(f'duplicate corpus inventory entry: {path}')
        inventory[path] = expected
    files = {str(p.relative_to(ROOT)): p for p in PACKAGE.rglob('*')
             if p.is_file() and p.name != 'SHA256SUMS' and package.include_evidence(p)}
    if set(files) != set(inventory):
        raise SystemExit('corpus inventory differs from declared assets; refresh explicitly')
    for path, file in files.items():
        if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != inventory[path]:
            raise SystemExit(f'corpus checksum mismatch: {path}')


def main(output):
    if output.exists():
        raise SystemExit('select a fresh output directory')
    output.mkdir(parents=True)
    check_inventory()
    corpus = load('xades-interop')

    def run(arguments, name):
        result = corpus.command(arguments, output / name)
        if result.returncode:
            raise SystemExit(f'live corpus check failed: {name}; inspect {output}')

    run([sys.executable, ROOT / 'scripts/test-xades-interop.py'], 'harness')
    run([sys.executable, ROOT / 'scripts/xades-interop.py', '--results', output / 'xmldsig'], 'xmldsig-run')
    count = check_goldens(PACKAGE / 'results', output / 'xmldsig')
    run([sys.executable, ROOT / 'scripts/xades-dss.py', '--results', output / 'dss'], 'dss-run')
    check_expectations(PACKAGE / 'dss-evidence/expectations.json', output / 'dss/summary.json')
    run([sys.executable, ROOT / 'scripts/investigate-xades-dss.py', '--output', output / 'binding'], 'binding-run')
    count += check_goldens(PACKAGE / 'dss-investigation', output / 'binding')
    check_expectations(PACKAGE / 'dss-investigation/expectations.json', output / 'binding/summary.json')
    run([sys.executable, ROOT / 'scripts/investigate-xades-dss.py', '--output', output / 'binding', '--strict-policy'], 'strict-run')
    check_expectations(PACKAGE / 'dss-investigation/strict-policy-expectations.json', output / 'binding/strict-policy-summary.json')
    print(f'verified: live XMLDSig/XAdES, {count} independent octet vectors, DSS and strict-policy expectations')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--output', required=True, type=Path)
    main(parser.parse_args().output.resolve())
