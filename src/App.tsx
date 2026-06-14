import React, { useState, useEffect } from 'react';
import { Shield, Server, AlertTriangle, Activity, Send, Lock, PlusCircle, CheckCircle, Clock } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

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
  const [activeTab, setActiveTab] = useState<'overview' | 'policies'>('overview');

  // Policy Form State
  const [policyType, setPolicyType] = useState('block_ip');
  const [ruleId, setRuleId] = useState('');
  const [content, setContent] = useState('');
  const [enforcementMode, setEnforcementMode] = useState('ENFORCE');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [pushStatus, setPushStatus] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await fetch('http://localhost:8080/api/v1/dashboard');
        if (!res.ok) throw new Error("Failed to fetch dashboard data");
        const data = await res.json();
        
        setAgents(data.agents || []);
        setIncidents(data.incidents || []);
      } catch (err) {
        console.error("Dashboard fetch error:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 3000); 
    return () => clearInterval(interval);
  }, []);

  const handlePushPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setPushStatus(null);
    try {
      const res = await fetch('http://localhost:8080/api/v1/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          policy_type: policyType,
          rule_id: ruleId,
          content,
          enforcement_mode: enforcementMode
        }),
      });
      if (!res.ok) throw new Error('Failed to push policy');
      setPushStatus("success");
      setRuleId('');
      setContent('');
      setTimeout(() => setPushStatus(null), 3000);
    } catch (err) {
      console.error(err);
      setPushStatus("error");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0b] text-gray-100 p-8 font-sans border-t-4 border-blue-600">
      <header className="mb-8 flex items-center justify-between border-b border-gray-800 pb-6">
        <div className="flex items-center gap-4">
          <div className="bg-blue-600/20 p-3 rounded-xl border border-blue-500/30">
            <Shield className="w-8 h-8 text-blue-500" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-gray-50 tracking-tight">Thor Control Plane</h1>
            <p className="text-gray-400 text-sm mt-1">Enterprise eBPF Fleet Management & Threat Intelligence</p>
          </div>
        </div>
        <div className="flex bg-gray-900 rounded-lg p-1 border border-gray-800">
          <button 
            onClick={() => setActiveTab('overview')}
            className={`px-6 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'overview' ? 'bg-blue-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}
          >
            Fleet Overview
          </button>
          <button 
            onClick={() => setActiveTab('policies')}
            className={`px-6 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'policies' ? 'bg-blue-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}
          >
            Policy Engine
          </button>
        </div>
      </header>

      {activeTab === 'overview' && (
        <motion.div initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }}>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <StatCard title="Total Agents" value={agents.length.toString()} icon={<Server className="w-5 h-5 text-blue-400" />} color="blue" />
            <StatCard title="Active Threats" value={incidents.filter(i => i.severity === 'CRITICAL').length.toString()} icon={<AlertTriangle className="w-5 h-5 text-red-500" />} color="red" />
            <StatCard title="Global EPS" value="1.2M" icon={<Activity className="w-5 h-5 text-green-400" />} color="green" />
            <StatCard title="Enforcement Mode" value="FAIL-CLOSE" icon={<Lock className="w-5 h-5 text-purple-400" />} color="purple" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 bg-[#121214] rounded-xl border border-gray-800 shadow-2xl overflow-hidden">
              <div className="p-5 border-b border-gray-800 bg-[#16161a]">
                <h2 className="text-lg font-semibold flex items-center gap-2"><Server className="w-5 h-5 text-gray-400"/> Agent Fleet Status</h2>
              </div>
              <div className="p-0 overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-[#1a1a1f] text-gray-400">
                    <tr>
                      <th className="px-6 py-3 font-medium">Hostname</th>
                      <th className="px-6 py-3 font-medium">IP Address</th>
                      <th className="px-6 py-3 font-medium">Status</th>
                      <th className="px-6 py-3 font-medium">CPU</th>
                      <th className="px-6 py-3 font-medium">Heartbeat</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800">
                    {loading && <tr><td colSpan={5} className="p-6 text-center text-gray-500">Connecting to agents...</td></tr>}
                    {!loading && agents.length === 0 && <tr><td colSpan={5} className="p-6 text-center text-gray-500">No agents registered.</td></tr>}
                    {agents.map(agent => (
                      <tr key={agent.agent_id} className="hover:bg-gray-800/50 transition-colors">
                        <td className="px-6 py-4 font-medium">{agent.hostname}</td>
                        <td className="px-6 py-4 font-mono text-gray-400">{agent.ip_address}</td>
                        <td className="px-6 py-4"><StatusBadge status={agent.status} /></td>
                        <td className="px-6 py-4">{agent.cpu_usage}%</td>
                        <td className="px-6 py-4 text-gray-500">-{agent.last_heartbeat}s</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="bg-[#121214] rounded-xl border border-gray-800 shadow-2xl overflow-hidden flex flex-col">
              <div className="p-5 border-b border-gray-800 bg-[#16161a]">
                <h2 className="text-lg font-semibold flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-gray-400"/> Live Incidents</h2>
              </div>
              <div className="p-5 overflow-y-auto flex-1 space-y-4">
                {loading && <p className="text-gray-500 text-center">Loading incidents...</p>}
                {!loading && incidents.length === 0 && <p className="text-gray-500 text-center">No active incidents.</p>}
                {incidents.map(inc => (
                  <div key={inc.incident_id} className="bg-[#1a1a1f] p-4 rounded-lg border border-gray-800 relative overflow-hidden group">
                    <div className={`absolute left-0 top-0 bottom-0 w-1 ${inc.severity === 'CRITICAL' ? 'bg-red-500' : 'bg-yellow-500'}`} />
                    <div className="flex justify-between items-start ml-2">
                      <span className={`font-bold text-xs px-2 py-0.5 rounded ${inc.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400' : 'bg-yellow-500/10 text-yellow-400'}`}>
                        {inc.severity}
                      </span>
                      <span className="text-xs text-gray-500 flex items-center gap-1"><Clock className="w-3 h-3"/> {new Date(inc.reported_at).toLocaleTimeString()}</span>
                    </div>
                    <p className="mt-3 text-sm text-gray-200 ml-2 leading-relaxed">{inc.description}</p>
                    <p className="mt-2 text-xs text-gray-500 ml-2 font-mono">ID: {inc.agent_id.split('-')[0]}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {activeTab === 'policies' && (
        <motion.div initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} className="max-w-4xl mx-auto">
          <div className="bg-[#121214] rounded-xl border border-gray-800 shadow-2xl overflow-hidden">
            <div className="p-6 border-b border-gray-800 bg-[#16161a]">
              <h2 className="text-xl font-semibold flex items-center gap-2">
                <Send className="w-5 h-5 text-blue-500" /> Push Fleet Policy
              </h2>
              <p className="text-gray-400 text-sm mt-1">Real-time eBPF map distribution to all connected edge nodes via gRPC stream.</p>
            </div>
            
            <form onSubmit={handlePushPolicy} className="p-8 space-y-6">
              <div className="grid grid-cols-2 gap-6">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-300">Policy Type</label>
                  <select 
                    value={policyType} 
                    onChange={e => setPolicyType(e.target.value)}
                    className="w-full bg-[#0a0a0b] border border-gray-700 rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 text-gray-100"
                  >
                    <option value="block_ip">Block IPv4/IPv6</option>
                    <option value="sigma_rule">Dynamic Sigma Rule</option>
                    <option value="rate_limit">CMS Rate Limit Threshold</option>
                    <option value="fail_mode">Toggle Fail-Close Mode</option>
                  </select>
                </div>
                
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-300">Enforcement Mode</label>
                  <select 
                    value={enforcementMode} 
                    onChange={e => setEnforcementMode(e.target.value)}
                    className="w-full bg-[#0a0a0b] border border-gray-700 rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 text-gray-100"
                  >
                    <option value="ENFORCE">ENFORCE (Drop Packets)</option>
                    <option value="AUDIT">AUDIT (Log Only)</option>
                  </select>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-300">Rule Identifier</label>
                <input 
                  type="text" 
                  required
                  value={ruleId}
                  onChange={e => setRuleId(e.target.value)}
                  placeholder="e.g. DROP_MALICIOUS_SUBNET_01"
                  className="w-full bg-[#0a0a0b] border border-gray-700 rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 text-gray-100"
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-300">Policy Content (CIDR, YAML, or Base64 Enum)</label>
                <textarea 
                  required
                  value={content}
                  onChange={e => setContent(e.target.value)}
                  rows={5}
                  placeholder="192.168.100.0/24"
                  className="w-full bg-[#0a0a0b] border border-gray-700 rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 text-gray-100 font-mono text-sm"
                />
              </div>

              <div className="pt-4 flex items-center justify-between">
                <div className="text-sm">
                  {pushStatus === 'success' && <span className="text-green-400 flex items-center gap-1"><CheckCircle className="w-4 h-4"/> Multi-Cast Stream Sent</span>}
                  {pushStatus === 'error' && <span className="text-red-400">Failed to push policy.</span>}
                </div>
                <button 
                  type="submit" 
                  disabled={isSubmitting}
                  className="bg-blue-600 hover:bg-blue-500 text-white px-8 py-3 rounded-lg font-medium transition-colors disabled:opacity-50 flex items-center gap-2 shadow-lg shadow-blue-500/20"
                >
                  {isSubmitting ? 'Distributing...' : <><PlusCircle className="w-5 h-5"/> Deploy to Fleet</>}
                </button>
              </div>
            </form>
          </div>
        </motion.div>
      )}
    </div>
  );
}

function StatCard({ title, value, color, icon }: { title: string, value: string, color: string, icon: React.ReactNode }) {
  return (
    <div className="bg-[#121214] p-6 rounded-xl border border-gray-800 shadow-lg relative overflow-hidden group">
      <div className="absolute -right-4 -top-4 opacity-5 transition-transform group-hover:scale-110">
        {React.cloneElement(icon as React.ReactElement, { className: 'w-32 h-32' })}
      </div>
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-gray-400 text-sm font-medium">{title}</h3>
        {icon}
      </div>
      <p className="text-3xl font-bold text-gray-50">{value}</p>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    ACTIVE: 'bg-green-500/10 text-green-400 border-green-500/20',
    DEGRADED: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    OFFLINE: 'bg-red-500/10 text-red-400 border-red-500/20',
  };
  return <span className={`px-2 py-1 rounded-md text-xs font-bold border ${styles[status] || 'bg-gray-800 text-gray-400 border-gray-700'}`}>{status}</span>;
}

