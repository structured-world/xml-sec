const status = document.querySelector('#status');
const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];

async function load(name) {
  const response = await fetch(name);
  if (!response.ok) throw Error(`${name}: HTTP ${response.status}`);
  return response.json();
}

function value(row, metric) {
  if (row.unsupported) return null;
  if (metric === 'p50_ns' || metric === 'p99_ns') return median(row.repetitions.map(x => x[metric])) / 1e6;
  if (metric === 'throughput') return row.input_bytes / (median(row.repetitions.map(x => x.p50_ns)) / 1e9) / 1048576;
  if (metric === 'cpu_seconds') return median(row.repetitions.flatMap(x => x.raw.map(y => y.cpu_seconds))) * 1000;
  // CLI samples each carry the process's RSS; a library repetition carries one.
  if (metric === 'rss_bytes') return Math.max(...row.repetitions.flatMap(x => x.rss_bytes ?? x.raw.map(y => y.rss_bytes))) / 1048576;
  const measured = row.memory?.[metric];
  return measured == null ? null : metric === 'allocation_calls' ? measured : measured / 1048576;
}

/** Render one level's chart from its own controls; levels are never ranked together. */
function section(prefix, results, select, describe) {
  const controls = [...document.querySelectorAll(`[data-section="${prefix}"]`)];
  const chart = document.querySelector(`#${prefix}-chart`);
  const boundary = document.querySelector(`#${prefix}-boundary`);
  function render() {
    const chosen = Object.fromEntries(controls.map(control => [control.dataset.field, control.value]));
    const rows = results.filter(row => select(row, chosen));
    if (boundary) boundary.textContent = describe(chosen) ?? '';
    const maximum = Math.max(0, ...rows.map(row => value(row, chosen.metric)).filter(x => x != null));
    chart.replaceChildren();
    if (!rows.length) {
      const empty = document.createElement('p');
      empty.className = 'muted';
      empty.textContent = 'This workload does not include this operation.';
      chart.append(empty);
    }
    for (const row of rows) {
      const number = value(row, chosen.metric);
      const container = document.createElement('div');
      container.className = 'row';
      const label = document.createElement('span');
      label.textContent = row.engine;
      const track = document.createElement('div');
      track.className = 'track';
      const bar = document.createElement('div');
      bar.className = 'bar';
      bar.style.width = number == null || !maximum ? '0' : `${number / maximum * 100}%`;
      track.append(bar);
      const text = document.createElement('span');
      text.className = 'value';
      text.textContent = row.unsupported ? 'Unsupported' : number == null ? 'Not measured' : number.toLocaleString('en', { maximumFractionDigits: 3 });
      if (row.unsupported) text.title = row.unsupported;
      container.append(label, track, text);
      chart.append(container);
    }
  }
  controls.forEach(control => control.addEventListener('change', render));
  render();
}

try {
  const [cli, library] = await Promise.all([load('comparison.json'), load('library.json')]);
  if (cli.schema !== 2 || !Array.isArray(cli.results) || !cli.results.length) throw Error('Invalid CLI measurement report');
  if (library.schema !== 1 || !Array.isArray(library.results) || !library.results.length) throw Error('Invalid library measurement report');
  status.textContent = `Measured ${cli.generated} · ${cli.environment.samples} samples × 3 repetitions · revision ${cli.source_revision.slice(0, 12)}`;
  document.querySelector('#metadata').textContent = JSON.stringify({ cli: { environment: cli.environment, binaries: cli.binaries, corpus: cli.corpus },
    library: { environment: library.environment, binaries: library.binaries } }, null, 2);
  // Payload cases name their document shape; workload cases name the workload.
  section('cli', cli.results, (row, chosen) => row.operation === chosen.operation && (row.shape ?? row.scenario) === chosen.shape
    && row.units === Number(chosen.units), () => null);
  section('library', library.results, (row, chosen) => row.operation === chosen.operation && row.scenario === chosen.shape
    && row.units === Number(chosen.units) && row.boundary === chosen.boundary, chosen => library.boundaries[chosen.boundary]);
} catch (error) {
  status.textContent = `Measurements unavailable: ${error.message}. No performance conclusions can be drawn.`;
}
