const status = document.querySelector('#status');
const controls = ['operation', 'shape', 'units', 'metric'].map(id => document.querySelector(`#${id}`));
const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
try {
  const response = await fetch('comparison.json');
  if (!response.ok) throw Error(`HTTP ${response.status}`);
  const report = await response.json();
  if (report.schema !== 1 || !Array.isArray(report.results) || !report.results.length) throw Error('Invalid measurement report');
  status.textContent = `Measured ${report.generated} · ${report.environment.samples} samples × 3 repetitions · revision ${report.source_revision.slice(0, 12)}`;
  document.querySelector('#metadata').textContent = JSON.stringify({ environment: report.environment, binaries: report.binaries, corpus: report.corpus }, null, 2);
  function render() {
    const [operation, shape, units, metric] = controls.map(x => x.value);
    const rows = report.results.filter(x => x.operation === operation && x.shape === shape && x.units === Number(units));
    const value = row => {
      if (metric === 'p50_ns' || metric === 'p99_ns') return median(row.repetitions.map(x => x[metric])) / 1e6;
      if (metric === 'throughput') return row.input_bytes / (median(row.repetitions.map(x => x.p50_ns)) / 1e9) / 1048576;
      if (metric === 'cpu_seconds') return median(row.repetitions.flatMap(x => x.raw.map(y => y.cpu_seconds))) * 1000;
      if (metric === 'rss_bytes') return Math.max(...row.repetitions.flatMap(x => x.raw.map(y => y.rss_bytes))) / 1048576;
      const measured = row.memory?.[metric];
      return measured == null ? null : metric === 'allocation_calls' ? measured : measured / 1048576;
    };
    const maximum = Math.max(0, ...rows.map(value).filter(x => x != null));
    const chart = document.querySelector('#chart');
    chart.replaceChildren();
    for (const row of rows) {
      const number = value(row);
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
      text.textContent = number == null ? 'Not measured' : number.toLocaleString('en', { maximumFractionDigits: 3 });
      container.append(label, track, text);
      chart.append(container);
    }
  }
  controls.forEach(control => control.addEventListener('change', render));
  render();
} catch (error) {
  status.textContent = `Measurements unavailable: ${error.message}. No performance conclusions can be drawn.`;
}
