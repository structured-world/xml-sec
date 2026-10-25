import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

export function percentile(values, percent) {
  if (!values.length || values.some(x => !Number.isFinite(x) || x < 0)) throw Error('Invalid samples');
  return [...values].sort((a, b) => a - b)[Math.ceil(percent * values.length / 100) - 1];
}

export function resources(text, platform) {
  const match = platform === 'darwin'
    ? text.match(/([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys[\s\S]*?(\d+)\s+maximum resident set size/)
    : text.match(/__METRICS ([\d.]+) ([\d.]+) (\d+)/);
  if (!match) throw Error('Missing process CPU/RSS report');
  return platform === 'darwin'
    ? { cpu_seconds: Number(match[2]) + Number(match[3]), rss_bytes: Number(match[4]) }
    : { cpu_seconds: Number(match[1]) + Number(match[2]), rss_bytes: Number(match[3]) * 1024 };
}

export function heapStats(memcheck, massif) {
  const total = memcheck.match(/total heap usage: ([\d,]+) allocs, [\d,]+ frees, ([\d,]+) bytes allocated/);
  const snapshots = [...massif.matchAll(/mem_heap_B=(\d+)\nmem_heap_extra_B=(\d+)/g)];
  if (!total || !snapshots.length) throw Error('Missing Valgrind allocation/heap report');
  return {
    allocation_calls: Number(total[1].replaceAll(',', '')),
    allocated_bytes: Number(total[2].replaceAll(',', '')),
    peak_heap_bytes: Math.max(...snapshots.map(m => Number(m[1]) + Number(m[2]))),
  };
}

/**
 * The reason an engine gave for refusing an input over one of its default resource
 * limits, or undefined for any other failure. A refusal is recorded per input and
 * never timed, so a later engine revision that accepts the input is measured again.
 */
export function policyRefusal(stderr) {
  return stderr.match(/policy violation: (.*exceeds policy maximum.*)/)?.[1].trim();
}

function checked(binary, args, options = {}) {
  const result = spawnSync(binary, args, { encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024, ...options });
  if (result.error || result.signal || result.status !== 0) throw Error(`${binary} failed: ${result.error ?? result.signal ?? result.status}\n${result.stderr}`);
  return result;
}

export function createEvidenceDirectory(output) {
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.mkdirSync(output); // Refuse to overwrite any existing evidence.
}

/** Operations measured for each workload family; `payload` is the original five shapes. */
export const SCENARIOS = {
  payload: ['sign', 'verify', 'encrypt', 'decrypt'],
  assertion: ['sign', 'verify'],
  element: ['encrypt', 'decrypt'],
  element_in_place: ['encrypt', 'decrypt'],
  xslt: ['sign', 'verify'],
};

/** Behavior observed at the pinned competitor revisions, per workload and operation; never timed. */
export const UNSUPPORTED = {
  bergshamra: {
    assertion: { sign: 'leaves the template X509Data empty; the signer certificate is never written' },
    element_in_place: { encrypt: 'CLI --node-id writes a standalone EncryptedData instead of replacing the element inside its document' },
    xslt: {
      sign: 'no XSLT transform',
      verify: 'no XSLT transform: an XSLT-transformed Reference fails with a digest mismatch',
    },
  },
};

/** Why `engine` cannot run `operation` of `scenario`, or undefined when it can. */
export function unsupported(engine, scenario, operation) {
  return UNSUPPORTED[engine]?.[scenario]?.[operation];
}

/** The XML document without the declaration and surrounding whitespace engines add on output. */
export function documentBody(bytes) {
  const text = bytes.toString('utf8').trim();
  const end = text.startsWith('<?xml') ? text.indexOf('?>') : -1;
  return (end < 0 ? text : text.slice(end + 2)).trim();
}

/**
 * Change one signed value so that every engine must reject the document. A replacement
 * that matches nothing would turn the rejection check into a check of an intact document.
 */
export function tamper(xml, scenario) {
  const [from, to] = {
    payload: ['<Payload Id="payload">', '<Payload Id="payload" altered="true">'],
    assertion: ['<saml:AttributeValue>value</saml:AttributeValue>', '<saml:AttributeValue>tampered</saml:AttributeValue>'],
    xslt: ['<Item n="0">value</Item>', '<Item n="0">tampered</Item>'],
  }[scenario];
  if (!xml.includes(from)) throw Error(`Tamper target missing for ${scenario}`);
  return xml.replace(from, to);
}

/**
 * Signature wrapping: an unsigned forged assertion with the signed assertion's ID and
 * another subject precedes the untouched signed one. A verifier that reported success
 * would leave the application free to read the forgery.
 */
export function wrap(xml) {
  const start = xml.indexOf('<saml:Assertion ID="assertion"');
  const close = '</saml:Assertion>';
  const end = xml.indexOf(close, start);
  if (start < 0 || end < 0) throw Error('Signed assertion missing');
  const signed = xml.slice(start, end + close.length);
  const signature = /<ds:Signature[\s>][\s\S]*<\/ds:Signature>/;
  const subject = '<saml:NameID>user@example.invalid</saml:NameID>';
  if (!signature.test(signed) || !signed.includes(subject)) throw Error('Signed assertion has no signature or subject');
  const forged = signed.replace(signature, '').replace(subject, '<saml:NameID>attacker@example.invalid</saml:NameID>');
  return xml.slice(0, start) + forged + signed + xml.slice(end + close.length);
}

/** Arguments for one engine and operation; `xmlsec` covers both xmlsec1-compatible CLIs. */
export function engineArguments(kind, scenario, operation, files) {
  const { template, signed, plain, encrypted, destination, corpus } = files;
  const file = name => path.join(corpus, name);
  if (kind === 'berg') {
    return {
      payload: {
        sign: ['sign', template, '--key-name', `bench:${file('private.pem')}`, '--output', destination],
        verify: ['verify', signed, '--key-name', `bench:${file('public.pem')}`, '--trusted-keys-only'],
        encrypt: ['encrypt', file('encryption.xml'), '--data', plain, '--keys-file', file('keys.xml'), '--output', destination],
        decrypt: ['decrypt', encrypted, '--keys-file', file('keys.xml'), '--output', destination],
      },
      // Bergshamra's documented SAML configuration: chain validation plus strict positions.
      assertion: {
        verify: ['verify', signed, '--trusted', file('root.pem'), '--untrusted', file('intermediate.pem'), '--enabled-key-data', 'x509', '--strict'],
      },
      element: {
        encrypt: ['encrypt', file('element.template.xml'), '--data', plain, '--cert', file('leaf.pem'), '--output', destination],
        decrypt: ['decrypt', encrypted, '--key', file('private.pem'), '--output', destination],
      },
      element_in_place: {
        decrypt: ['decrypt', encrypted, '--key', file('private.pem'), '--output', destination],
      },
    }[scenario]?.[operation];
  }
  const recipient = ['--pubkey-cert-pem:recipient', file('leaf.pem'), '--session-key', 'aes-256'];
  return {
    payload: {
      sign: ['sign', '--privkey-pem:bench', file('private.pem'), '--id-attr:Id', 'Payload', '--output', destination, template],
      verify: ['verify', '--pubkey-pem:bench', file('public.pem'), '--id-attr:Id', 'Payload', signed],
      encrypt: ['encrypt', '--keys-file', file('keys.xml'), '--binary-data', plain, '--output', destination, file('encryption.xml')],
      decrypt: ['decrypt', '--keys-file', file('keys.xml'), '--output', destination, encrypted],
    },
    assertion: {
      sign: ['sign', '--privkey-pem:bench', `${file('private.pem')},${file('leaf.pem')}`, '--id-attr:ID', 'urn:oasis:names:tc:SAML:2.0:assertion:Assertion', '--output', destination, template],
      verify: ['verify', '--trusted-pem', file('root.pem'), '--untrusted-pem', file('intermediate.pem'), '--id-attr:ID', 'urn:oasis:names:tc:SAML:2.0:assertion:Assertion', signed],
    },
    element: {
      encrypt: ['encrypt', ...recipient, '--xml-data', plain, '--output', destination, file('element.template.xml')],
      decrypt: ['decrypt', '--privkey-pem:recipient', file('private.pem'), '--output', destination, encrypted],
    },
    element_in_place: {
      encrypt: ['encrypt', ...recipient, '--id-attr:Id', 'Payment', '--xml-data', plain, '--node-id', 'payment', '--output', destination, file('element.template.xml')],
      decrypt: ['decrypt', '--privkey-pem:recipient', file('private.pem'), '--output', destination, encrypted],
    },
    xslt: {
      sign: ['sign', '--privkey-pem:bench', file('private.pem'), '--id-attr:Id', 'List', '--output', destination, template],
      verify: ['verify', '--pubkey-pem:bench', file('public.pem'), '--id-attr:Id', 'List', signed],
    },
  }[scenario]?.[operation];
}

/** Input files for one case: what each operation reads. */
export function caseFiles(item) {
  const { name, scenario, units } = item;
  return {
    template: `${name}.template.xml`,
    signed: `${name}.signed.xml`,
    plain: { element: `element-${units}.plain.xml`, element_in_place: `order-${units}.plain.xml` }[scenario] ?? `${name}.plain.xml`,
    encrypted: `${name}.encrypted.xml`,
  };
}

function main() {
  // Keep system-tool reports independent of the caller's locale.
  process.env.LC_ALL = 'C';
  const [output, sampleText = '30', heapMode = ''] = process.argv.slice(2);
  const samples = Number(sampleText);
  if (!output || !/^\d+$/.test(sampleText) || !Number.isSafeInteger(samples) || samples < 1 || samples > 1000 || !['', '--heap'].includes(heapMode)) throw Error('Usage: compare-security.mjs NEW_OUTPUT_DIR SAMPLES [--heap]');
  if (!['linux', 'darwin'].includes(process.platform)) throw Error('CPU/RSS requires Linux or macOS');
  if (heapMode && process.platform !== 'linux') throw Error('Valgrind heap comparison requires Linux');
  const binaries = ['XML_SEC_BENCH_BIN', 'BERGSHAMRA_BIN', 'XMLSEC1_BIN', 'BENCH_EXPORT_BIN'].map(name => {
    if (!process.env[name]) throw Error(`Missing ${name}`);
    return fs.realpathSync(process.env[name]);
  });
  if (heapMode) checked('valgrind', ['--version']);
  createEvidenceDirectory(output);
  const root = fs.realpathSync(output);
  const corpus = path.join(root, 'corpus');
  checked(binaries[3], ['--export', corpus]);
  const file = name => path.join(corpus, name);
  const engines = [
    { name: 'xml-sec / xmloxide / RustCrypto', id: 'xml-sec', kind: 'xmlsec', binary: binaries[0], backend: ['--xml-backend', 'xmloxide'] },
    { name: 'xml-sec / roxmltree / RustCrypto', id: 'xml-sec', kind: 'xmlsec', binary: binaries[0], backend: ['--xml-backend', 'roxmltree'] },
    { name: 'bergshamra / Uppsala / RustCrypto', id: 'bergshamra', kind: 'berg', binary: binaries[1] },
    { name: 'libxmlsec1 / libxml2 / OpenSSL', id: 'libxmlsec1', kind: 'xmlsec', binary: binaries[2] },
  ];
  // macOS time strips DYLD_*; set loader paths immediately before the child exec.
  const loader = process.platform === 'darwin' && process.env.DYLD_LIBRARY_PATH
    ? ['/usr/bin/env', `DYLD_LIBRARY_PATH=${process.env.DYLD_LIBRARY_PATH}`] : [];
  const command = (engine, item, operation, destination, input) => {
    const files = caseFiles(item);
    const args = engineArguments(engine.kind, item.scenario, operation, {
      template: file(files.template), signed: input ?? file(files.signed), plain: file(files.plain),
      encrypted: input ?? file(files.encrypted), destination, corpus,
    });
    return [...loader, engine.binary, args[0], ...(engine.backend ?? []), ...args.slice(1)];
  };
  const invoke = cmd => checked(cmd[0], cmd.slice(1), { stdio: ['ignore', 'ignore', 'pipe'] });
  // Run a validation command; return the engine's resource-policy refusal, if any.
  const attempt = cmd => {
    const result = spawnSync(cmd[0], cmd.slice(1), { encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'ignore', 'pipe'] });
    if (!result.error && !result.signal && result.status === 0) return undefined;
    const refusal = result.error || result.signal ? undefined : policyRefusal(result.stderr);
    if (refusal) return refusal;
    throw Error(`${cmd[0]} failed: ${result.error ?? result.signal ?? result.status}\n${result.stderr}`);
  };
  const reject = (engine, item, input, what) => {
    const invalid = command(engine, item, 'verify', null, input);
    const rejection = spawnSync(invalid[0], invalid.slice(1), { encoding: 'utf8', timeout: 120000 });
    // A crash/timeout is not successful verification rejection.
    if (rejection.error || rejection.signal || rejection.status !== 1) throw Error(`Invalid ${what} rejection: ${engine.name}, ${item.name}`);
  };
  const cases = JSON.parse(fs.readFileSync(file('cases.json'))).map(item => ({ scenario: 'payload', ...item }));
  const results = [];
  const rawDirectory = path.join(root, 'raw');
  fs.mkdirSync(rawDirectory);
  for (const item of cases) {
    const { name, scenario } = item;
    const operations = SCENARIOS[scenario];
    // Engines that refused this case under their default resource policy, per operation.
    const refused = new Map();
    const blocked = (engine, operation) => unsupported(engine.id, scenario, operation) ?? refused.get(`${engine.name}/${operation}`);
    const able = operation => engines.filter(engine => !blocked(engine, operation));
    const refuse = (engine, operation, reason) => refused.set(`${engine.name}/${operation}`, `refused under the engine's default policy: ${reason}`);
    if (operations.includes('sign')) {
      // Every signer's output must verify with every verifier, and a changed signed value
      // (and, for assertions, a wrapped forgery) must be rejected before anything is timed.
      const outputs = [];
      for (const [index, signer] of able('sign').entries()) {
        const signed = file(`${name}.signed-${index}.xml`);
        const refusal = attempt(command(signer, item, 'sign', signed));
        if (refusal) { refuse(signer, 'sign', refusal); continue; }
        if (scenario === 'assertion' && !fs.readFileSync(signed, 'utf8').includes('X509Certificate>')) throw Error(`No signer certificate: ${signer.name}, ${name}`);
        outputs.push(signed);
      }
      if (!outputs.length) throw Error(`No engine signed ${name}`);
      for (const signed of outputs) for (const verifier of able('verify')) {
        const refusal = attempt(command(verifier, item, 'verify', null, signed));
        if (refusal) refuse(verifier, 'verify', refusal);
      }
      fs.copyFileSync(outputs[0], file(`${name}.signed.xml`));
      const signedText = fs.readFileSync(file(`${name}.signed.xml`), 'utf8');
      const tampered = file(`${name}.tampered.xml`);
      fs.writeFileSync(tampered, tamper(signedText, scenario));
      // A refusing verifier says nothing about tamper detection, so it is not counted.
      for (const verifier of able('verify')) reject(verifier, item, tampered, 'tampered');
      if (scenario === 'assertion') {
        const wrapped = file(`${name}.wrapped.xml`);
        fs.writeFileSync(wrapped, wrap(signedText));
        for (const verifier of able('verify')) reject(verifier, item, wrapped, 'wrapped');
      }
    }
    if (operations.includes('encrypt')) {
      const plain = fs.readFileSync(file(caseFiles(item).plain));
      const outputs = [];
      for (const [index, encryptor] of able('encrypt').entries()) {
        const encrypted = file(`${name}.encrypted-${index}.xml`);
        const refusal = attempt(command(encryptor, item, 'encrypt', encrypted));
        if (refusal) { refuse(encryptor, 'encrypt', refusal); continue; }
        outputs.push({ encryptor, encrypted });
      }
      if (!outputs.length) throw Error(`No engine encrypted ${name}`);
      for (const { encryptor, encrypted } of outputs) for (const decryptor of able('decrypt')) {
        const decrypted = file(`${name}.decrypted.xml`);
        const refusal = attempt(command(decryptor, item, 'decrypt', decrypted, encrypted));
        if (refusal) { refuse(decryptor, 'decrypt', refusal); continue; }
        // Byte payloads must round-trip exactly; XML results may differ only in the
        // declaration and surrounding whitespace the writing engine adds.
        const output = fs.readFileSync(decrypted);
        const equal = scenario === 'payload' ? output.equals(plain) : documentBody(output) === documentBody(plain);
        if (!equal) throw Error(`Plaintext mismatch: ${encryptor.name} -> ${decryptor.name}, ${name}`);
      }
      fs.copyFileSync(outputs[0].encrypted, file(`${name}.encrypted.xml`));
    }
    for (const operation of operations) {
      const supported = able(operation);
      const entries = supported.map((engine, index) => ({ level: 'cli', engine: engine.name, operation, ...item,
        boundary: 'fresh CLI process + key loading + file I/O + operation',
        repetitions: [], memory: null, commands: command(engine, item, operation, file(`${name}.${operation}-${index}.output`)) }));
      for (let repetition = 0; repetition < 3; repetition++) {
        const observations = entries.map(() => []);
        for (let sample = 0; sample < samples; sample++) {
          // Rotate order to avoid giving one engine every first/cold slot.
          for (let step = 0; step < entries.length; step++) {
            const index = (step + sample + repetition) % entries.length;
            const cmd = entries[index].commands;
            const timeArgs = process.platform === 'darwin' ? ['-l'] : ['-f', '__METRICS %U %S %M'];
            const start = performance.now();
            const measured = checked('/usr/bin/time', [...timeArgs, ...cmd], { stdio: ['ignore', 'ignore', 'pipe'] });
            const elapsed = (performance.now() - start) * 1e6;
            observations[index].push({ wall_ns: elapsed, ...resources(measured.stderr, process.platform) });
          }
        }
        observations.forEach((raw, index) => entries[index].repetitions.push({ raw,
          p50_ns: percentile(raw.map(x => x.wall_ns), 50), p95_ns: percentile(raw.map(x => x.wall_ns), 95), p99_ns: percentile(raw.map(x => x.wall_ns), 99) }));
      }
      const files = caseFiles(item);
      for (let index = 0; index < entries.length; index++) {
        const entry = entries[index];
        const id = `${name}-${operation}-${index}`;
        const input = { sign: files.template, verify: files.signed, encrypt: files.plain, decrypt: files.encrypted }[operation];
        entry.input_bytes = fs.statSync(file(input)).size;
        entry.output_bytes = operation === 'verify' ? null : fs.statSync(file(`${name}.${operation}-${index}.output`)).size;
        entry.output_amplification = entry.output_bytes === null ? null : entry.output_bytes / entry.input_bytes;
        if (heapMode) {
          const log = path.join(rawDirectory, `${id}.memcheck.txt`);
          const massif = path.join(rawDirectory, `${id}.massif.txt`);
          const cmd = entry.commands;
          checked('valgrind', ['--tool=memcheck', '--leak-check=no', `--log-file=${log}`, ...cmd], { stdio: ['ignore', 'ignore', 'pipe'] });
          checked('valgrind', ['--tool=massif', '--stacks=no', '--time-unit=B', `--massif-out-file=${massif}`, ...cmd], { stdio: ['ignore', 'ignore', 'pipe'] });
          entry.memory = heapStats(fs.readFileSync(log, 'utf8'), fs.readFileSync(massif, 'utf8'));
        }
      }
      results.push(...entries);
      for (const engine of engines.filter(engine => blocked(engine, operation))) {
        results.push({ level: 'cli', engine: engine.name, operation, ...item, unsupported: blocked(engine, operation) });
      }
    }
  }
  const digest = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  const report = { schema: 2, generated: new Date().toISOString(), source_revision: checked('git', ['rev-parse', 'HEAD']).stdout.trim(),
    environment: { platform: process.platform, architecture: process.arch, cpu: os.cpus()[0]?.model, node: process.version, samples, repetitions: 3,
      timing: 'unprofiled, warm filesystem cache, fresh processes; includes measurement wrapper and process launch',
      memory: 'RSS includes full process lifetime; optional Valgrind heap excludes stacks and non-malloc mmap allocations; profiling timing never used' },
    binaries: binaries.slice(0, 3).map(binary => {
      const cmd = [...loader, binary, '--version'];
      return { sha256: digest(binary), bytes: fs.statSync(binary).size, version: checked(cmd[0], cmd.slice(1)).stdout.trim() };
    }),
    corpus: fs.readdirSync(corpus).filter(name => /\.(template|plain)\.xml$/.test(name) || /^[a-z_]+-\d+\.signed\.xml$/.test(name) || ['keys.xml', 'encryption.xml', 'element.template.xml', 'private.pem', 'public.pem', 'leaf.pem', 'intermediate.pem', 'root.pem', 'cases.json'].includes(name)).map(name => ({ name, sha256: digest(file(name)) })), results };
  fs.writeFileSync(path.join(root, 'comparison.json'), JSON.stringify(report));
  const measured = results.filter(entry => !entry.unsupported).length;
  console.log(`Validated ${measured} comparable cases, ${results.length - measured} unsupported; ${samples} samples x 3 repetitions, heap=${Boolean(heapMode)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
