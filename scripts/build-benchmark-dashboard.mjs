import * as fs from 'node:fs';
import * as path from 'node:path';
const [input, output] = process.argv.slice(2);
if (!input || !output) throw Error('Usage: build-benchmark-dashboard.mjs COMPARISON_DIR NEW_SITE_DIR');
const report = JSON.parse(fs.readFileSync(path.join(input, 'comparison.json')));
if (report.schema !== 1 || report.results.length !== 160) throw Error('Expected all 160 validated comparison cases');
// Runtime absolute paths are useful locally, not public dashboard content.
for (const entry of report.results) delete entry.commands;
fs.mkdirSync(output);
for (const file of ['index.html', 'app.js', 'style.css']) fs.copyFileSync(path.join('benchmarks/dashboard', file), path.join(output, file));
fs.writeFileSync(path.join(output, 'comparison.json'), JSON.stringify(report));
