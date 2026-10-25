import * as fs from 'node:fs';
import * as path from 'node:path';
const [input, output] = process.argv.slice(2);
if (!input || !output) throw Error('Usage: build-benchmark-dashboard.mjs COMPARISON_DIR NEW_SITE_DIR');
const report = JSON.parse(fs.readFileSync(path.join(input, 'comparison.json')));
const library = JSON.parse(fs.readFileSync(path.join(input, 'library.json')));
// CLI: 5 payload shapes x 2 sizes x 4 operations x 4 engines, plus 4 workloads x 2 sizes
// x 2 operations x 4 engines. Library: 4 workloads x 2 sizes x 2 operations x 2
// boundaries x 3 engines. An engine without the capability has an unsupported entry.
const EXPECTED_CLI = 160 + 64;
const EXPECTED_LIBRARY = 96;
if (report.schema !== 2 || report.results.length !== EXPECTED_CLI) throw Error(`Expected all ${EXPECTED_CLI} command-line entries`);
if (library.schema !== 1 || library.results.length !== EXPECTED_LIBRARY) throw Error(`Expected all ${EXPECTED_LIBRARY} library entries`);
if ([...report.results, ...library.results].some(entry => !entry.unsupported && !entry.repetitions?.length)) throw Error('A supported entry has no measurements');
// Runtime absolute paths are useful locally, not public dashboard content.
for (const entry of report.results) delete entry.commands;
fs.mkdirSync(output);
for (const file of ['index.html', 'app.js', 'style.css']) fs.copyFileSync(path.join('benchmarks/dashboard', file), path.join(output, file));
fs.writeFileSync(path.join(output, 'comparison.json'), JSON.stringify(report));
fs.writeFileSync(path.join(output, 'library.json'), JSON.stringify(library));
