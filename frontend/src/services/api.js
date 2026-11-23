const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';
async function get(path) {
  const response = await fetch(`${BASE}${path}`);
  if (!response.ok) throw new Error(`API returned ${response.status}`);
  return response.json();
}
export const api = { health: () => get('/health'), stats: () => get('/stats'), alerts: () => get('/alerts'), ips: () => get('/ips'), logs: (query = '') => get(`/logs?limit=1000${query}`) };
