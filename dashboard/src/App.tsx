import React, { useState, useEffect } from 'react';

// أنواع البيانات (Types)
interface Agent {
  agent_id: string;
  hostname: string;
  ip_address: string;
  status: 'ACTIVE' | 'DEGRADED' | 'OFFLINE';
  cpu_usage: number;
  memory_mb: number;
  last_heartbeat: string;
}

interface Incident {
  incident_id: string;
  agent_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  reported_at: string;
}

export default function App() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  // محاكاة جلب البيانات من REST API (استبدلها بـ fetch الحقيقي)
  useEffect(() => {
    const fetchData = async () => {
      // const res = await fetch('http://localhost:8080/api/v1/dashboard');
      // const data = await res.json();
      
      // بيانات وهمية للعرض التوضيحي
      setAgents([
        { agent_id: 'agent-001', hostname: 'db-prod-01', ip_address: '10.0.1.50', status: 'ACTIVE', cpu_usage: 12.5, memory_mb: 1024, last_heartbeat: new Date().toISOString() },
        { agent_id: 'agent-002', hostname: 'web-prod-02', ip_address: '10.0.1.51', status: 'DEGRADED', cpu_usage: 85.0, memory_mb: 3500, last_heartbeat: new Date().toISOString() },
      ]);
      setIncidents([
        { incident_id: 'inc-992', agent_id: 'agent-002', severity: 'CRITICAL', description: 'Detected malicious JA4 fingerprint (C2 Beacon)', reported_at: new Date().toISOString() },
      ]);
      setLoading(false);
    };
    fetchData();
    const interval = setInterval(fetchData, 5000); // تحديث كل 5 ثوانٍ
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div className="p-8 text-white">Loading Thor Control Plane...</div>;

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-8 font-sans">
      <header className="mb-8 border-b border-gray-700 pb-4">
        <h1 className="text-3xl font-bold text-blue-500">🛡️ Thor Control Plane</h1>
        <p className="text-gray-400">Enterprise Fleet Management & Threat Intelligence</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <StatCard title="Total Agents" value={agents.length.toString()} color="blue" />
        <StatCard title="Active Threats" value={incidents.filter(i => i.severity === 'CRITICAL').length.toString()} color="red" />
        <StatCard title="System Health" value="98.5%" color="green" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* جدول الوكلاء */}
        <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
          <h2 className="text-xl font-semibold mb-4">Agent Fleet Status</h2>
          <table className="w-full text-left">
            <thead>
              <tr className="text-gray-400 border-b border-gray-700">
                <th className="pb-2">Hostname</th>
                <th className="pb-2">IP Address</th>
                <th className="pb-2">Status</th>
                <th className="pb-2">CPU</th>
              </tr>
            </thead>
            <tbody>
              {agents.map(agent => (
                <tr key={agent.agent_id} className="border-b border-gray-700 hover:bg-gray-700">
                  <td className="py-3">{agent.hostname}</td>
                  <td className="py-3 font-mono text-sm">{agent.ip_address}</td>
                  <td className="py-3">
                    <StatusBadge status={agent.status} />
                  </td>
                  <td className="py-3">{agent.cpu_usage}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* جدول الحوادث */}
        <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
          <h2 className="text-xl font-semibold mb-4">Live Incidents</h2>
          <div className="space-y-4">
            {incidents.map(inc => (
              <div key={inc.incident_id} className="bg-gray-900 p-4 rounded border-l-4 border-red-500">
                <div className="flex justify-between items-start">
                  <span className="font-bold text-red-400">{inc.severity}</span>
                  <span className="text-xs text-gray-500">{new Date(inc.reported_at).toLocaleTimeString()}</span>
                </div>
                <p className="mt-2 text-sm">{inc.description}</p>
                <p className="mt-1 text-xs text-gray-400">Agent: {inc.agent_id}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// مكونات مساعدة (Helper Components)
function StatCard({ title, value, color }: { title: string, value: string, color: string }) {
  const colors: Record<string, string> = { blue: 'text-blue-400', red: 'text-red-400', green: 'text-green-400' };
  return (
    <div className="bg-gray-800 p-6 rounded-lg shadow">
      <h3 className="text-gray-400 text-sm uppercase">{title}</h3>
      <p className={`text-3xl font-bold mt-2 ${colors[color]}`}>{value}</p>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    ACTIVE: 'bg-green-900 text-green-300',
    DEGRADED: 'bg-yellow-900 text-yellow-300',
    OFFLINE: 'bg-red-900 text-red-300',
  };
  return <span className={`px-2 py-1 rounded text-xs font-bold ${styles[status] || 'bg-gray-700'}`}>{status}</span>;
}
