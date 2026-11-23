const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';
async function get(path) {
  const response = await fetch(`${BASE}${path}`);
  if (!response.ok) throw new Error(`API returned ${response.status}`);
  return response.json();
}
async function post(path, body) {
  const response = await fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error(`API returned ${response.status}`);
  return response.json();
}
export const api = {
  health: () => get('/health'), datasets: () => get('/datasets'), datasetStats: () => get('/datasets/stats'),
  selectDataset: source => post('/datasets/select', { source }), stats: () => get('/stats'), alerts: () => get('/alerts'),
  ips: () => get('/ips'), activity: () => get('/activity'), logs: (query = '') => get(`/logs?limit=1000${query}`)
};
