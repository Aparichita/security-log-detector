import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, AreaChart, Area, XAxis, YAxis, CartesianGrid } from 'recharts';
const colors = { CRITICAL: '#ff5364', HIGH: '#ff9e45', MEDIUM: '#f3c64e' };
export function SeverityChart({ alerts }) {
  const data = ['CRITICAL','HIGH','MEDIUM'].map(name => ({ name, value: alerts.filter(a => a.severity === name).length })).filter(x => x.value);
  return <div className="chart-wrap">{data.length ? <ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={data} dataKey="value" nameKey="name" innerRadius={62} outerRadius={86} paddingAngle={4}>{data.map(x => <Cell key={x.name} fill={colors[x.name]} />)}</Pie><Tooltip contentStyle={{background:'#151e29',border:'1px solid #293545'}} /></PieChart></ResponsiveContainer> : <div className="empty">No alerts in this dataset</div>}</div>;
}
export function ActivityChart({ activity }) {
  const data = (activity || []).map(row => ({time: new Date(row.timestamp).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}), events: row.events}));
  return <div className="activity-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data}><defs><linearGradient id="fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#48c8ad" stopOpacity={.24}/><stop offset="100%" stopColor="#48c8ad" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#202b38" vertical={false}/><XAxis dataKey="time" stroke="#647286" tick={{fontSize:10}} minTickGap={32}/><YAxis stroke="#647286" tick={{fontSize:10}} width={28}/><Tooltip contentStyle={{background:'#151e29',border:'1px solid #293545'}}/><Area type="monotone" dataKey="events" stroke="#48c8ad" fill="url(#fill)" strokeWidth={2}/></AreaChart></ResponsiveContainer></div>;
}
