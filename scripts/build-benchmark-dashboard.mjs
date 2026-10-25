import * as fs from 'node:fs';
import * as path from 'node:path';
const [input, output] = process.argv.slice(2);
if (!input || !output) throw Error('Usage: build-benchmark-dashboard.mjs COMPARISON_DIR NEW_SITE_DIR');
const report = JSON.parse(fs.readFileSync(path.join(input, 'comparison.json')));
// 5 payload shapes x 2 sizes x 4 operations x 4 engines, plus 4 scenarios x 2 sizes x
// 2 operations x 4 engines; an engine without the capability has an unsupported entry.
const EXPECTED_RESULTS = 160 + 64;
if (report.schema !== 2 || report.results.length !== EXPECTED_RESULTS) throw Error(`Expected all ${EXPECTED_RESULTS} comparison entries`);
if (report.results.some(entry => !entry.unsupported && !entry.repetitions?.length)) throw Error('A supported entry has no measurements');
// Runtime absolute paths are useful locally, not public dashboard content.
for (const entry of report.results) delete entry.commands;
fs.mkdirSync(output);
for (const file of ['index.html', 'app.js', 'style.css']) fs.copyFileSync(path.join('benchmarks/dashboard', file), path.join(output, file));
fs.writeFileSync(path.join(output, 'comparison.json'), JSON.stringify(report));
