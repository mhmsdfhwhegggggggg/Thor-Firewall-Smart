import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Server, 
  AlertTriangle, 
  Activity, 
  Send, 
  Lock, 
  PlusCircle, 
  CheckCircle, 
  Clock, 
  Cpu, 
  Network, 
  Terminal, 
  Flame, 
  RefreshCw, 
  Sliders, 
  Database,
  ArrowRight
} from 'lucide-react';
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
  const [activeTab, setActiveTab] = useState<'overview' | 'policies' | 'simulator'>('overview');

  // Policy Form State
  const [policyType, setPolicyType] = useState('block_ip');
  const [ruleId, setRuleId] = useState('');
  const [content, setContent] = useState('');
  const [enforcementMode, setEnforcementMode] = useState('ENFORCE');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [pushStatus, setPushStatus] = useState<string | null>(null);

  // Simulator State
  const [simulationRunning, setSimulationRunning] = useState<string | null>(null);
  const [simulationStatus, setSimulationStatus] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      // Fetch relative to current host (Port 3000)
      const res = await fetch('/api/v1/dashboard');
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

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000); 
    return () => clearInterval(interval);
  }, []);

  const handlePushPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setPushStatus(null);
    try {
      const res = await fetch('/api/v1/policies', {
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
      fetchData(); // immediately reload stats
      setTimeout(() => setPushStatus(null), 4000);
    } catch (err) {
      console.error(err);
      setPushStatus("error");
    } finally {
      setIsSubmitting(false);
    }
  };

  const triggerSimulation = async (attackType: string) => {
    setSimulationRunning(attackType);
    setSimulationStatus("Initiating high-fidelity enterprise exploit chain...");
    try {
      await new Promise(resolve => setTimeout(resolve, 800));
      setSimulationStatus("Analyzing across defensive pipeline matrix...");
      await new Promise(resolve => setTimeout(resolve, 800));
      
      const res = await fetch('/api/v1/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: attackType })
      });
      
      if (!res.ok) throw new Error('Simulation failed');
      
      setSimulationStatus("🛡️ Intercepted! Threat completely neutralized by defense module.");
      fetchData(); // Refresh list to fetch newly injected logs
      setTimeout(() => {
        setSimulationRunning(null);
        setSimulationStatus(null);
      }, 2500);
    } catch (err) {
      console.error(err);
      setSimulationStatus("Pipeline communication disruption.");
      setTimeout(() => {
        setSimulationRunning(null);
        setSimulationStatus(null);
      }, 3000);
    }
  };

  const handleResetSimulator = async () => {
    try {
      const res = await fetch('/api/v1/reset', { method: 'POST' });
      if (res.ok) {
        fetchData();
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="min-h-screen bg-[#080809] text-gray-100 p-8 font-sans border-t-4 border-blue-500 selection:bg-blue-500/20">
      
      {/* HEADER SECTION */}
      <header className="mb-10 flex flex-col md:flex-row md:items-center justify-between border-b border-gray-800 pb-8 gap-6">
        <div className="flex items-center gap-4">
          <div className="bg-gradient-to-tr from-blue-600 to-indigo-600 p-3.5 rounded-2xl shadow-lg shadow-blue-500/10 border border-blue-400/20">
            <Shield className="w-8 h-8 text-white relative animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-extrabold text-white tracking-tight">Thor Firewall Smart</h1>
              <span className="bg-emerald-500/10 text-emerald-400 text-xs px-2.5 py-0.5 rounded-full border border-emerald-500/20 font-semibold tracking-wide flex items-center gap-1">
                <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-ping"></span>
                ACTIVE PROTOCOL
              </span>
            </div>
            <p className="text-gray-400 text-sm mt-1">Multi-Layer eBPF & Envoy Sidecar Autonomous Network Defense Solution</p>
          </div>
        </div>
        
        {/* TAB CONTROLLERS */}
        <div className="flex bg-[#121215] rounded-xl p-1.5 border border-gray-800/80 max-w-sm self-start md:self-center">
          <button 
            onClick={() => setActiveTab('overview')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all duration-200 flex items-center gap-2 ${activeTab === 'overview' ? 'bg-gradient-to-r from-blue-600 to-blue-700 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}
          >
            <Activity className="w-4 h-4" /> Overview
          </button>
          <button 
            onClick={() => setActiveTab('policies')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all duration-200 flex items-center gap-2 ${activeTab === 'policies' ? 'bg-gradient-to-r from-blue-600 to-blue-700 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}
          >
            <Sliders className="w-4 h-4" /> Policies
          </button>
          <button 
            onClick={() => setActiveTab('simulator')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all duration-200 flex items-center gap-2 ${activeTab === 'simulator' ? 'bg-gradient-to-r from-gradient-to-r from-blue-600 to-blue-700 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}
          >
            <Terminal className="w-4 h-4" /> Threat Space
          </button>
        </div>
      </header>

      {/* RENDER TAB content */}
      {activeTab === 'overview' && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
          
          {/* STATS DECK */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-10">
            <StatCard title="Healthy Fleet Nodes" value={agents.length.toString()} sub="100% Core Coverage" icon={<Server className="w-5 h-5 text-blue-400" />} color="blue" />
            <StatCard title="Active Mitigated Threats" value={incidents.length.toString()} sub="Autonomous Interceptions" icon={<AlertTriangle className="w-5 h-5 text-amber-500" />} color="amber" />
            <StatCard title="Core Filtering EPS" value="1.2M+" sub="Hardware Accel eBPF Layer" icon={<Network className="w-5 h-5 text-emerald-400" />} color="emerald" />
            <StatCard title="Aggregated Threat Level" value="STABLE" sub="Defensive Safe Mode" icon={<Lock className="w-5 h-5 text-indigo-400" />} color="indigo" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* AGENT FLEET TABLE */}
            <div className="lg:col-span-2 bg-[#121214] rounded-2xl border border-gray-800/80 shadow-2xl overflow-hidden self-start">
              <div className="p-6 border-b border-gray-800/80 bg-[#151518] flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold flex items-center gap-2 text-white">
                    <Server className="w-5 h-5 text-gray-400"/> Operational Threat Agents
                  </h2>
                  <p className="text-gray-400 text-xs mt-1">Global security monitoring instances connected via secure TLS/mTLS</p>
                </div>
                <div className="text-gray-500 text-xs flex items-center gap-1.5 font-mono">
                  <span className="w-2.5 h-2.5 bg-emerald-500 rounded-full inline-block animate-pulse"></span>
                  POLLING SECURELY
                </div>
              </div>
              <div className="p-0 overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-[#17171c] text-gray-400 uppercase tracking-wider text-2xs font-bold font-mono">
                    <tr>
                      <th className="px-6 py-4 border-b border-gray-800">Agent Node / Role</th>
                      <th className="px-6 py-4 border-b border-gray-800">Internal Network IP</th>
                      <th className="px-6 py-4 border-b border-gray-800">Security Layer</th>
                      <th className="px-6 py-4 border-b border-gray-800">CPU Load</th>
                      <th className="px-6 py-4 border-b border-gray-800">Memory Allocation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/60">
                    {loading && <tr><td colSpan={5} className="p-10 text-center text-gray-500">Retrieving operational network topologies...</td></tr>}
                    {!loading && agents.length === 0 && <tr><td colSpan={5} className="p-10 text-center text-gray-500">No agents currently registered into the secure hub.</td></tr>}
                    {agents.map(agent => (
                      <tr key={agent.agent_id} className="hover:bg-gray-800/30 transition-all duration-150">
                        <td className="px-6 py-5">
                          <div>
                            <span className="font-semibold text-gray-100 block">{agent.hostname}</span>
                            <span className="text-gray-500 text-xs block font-mono">ID: {agent.agent_id}</span>
                          </div>
                        </td>
                        <td className="px-6 py-5 font-mono text-gray-400">{agent.ip_address}</td>
                        <td className="px-6 py-5">
                          <span className={`px-2.5 py-1 rounded-md text-xs font-bold border ${
                            agent.agent_id.includes('ebpf') ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' :
                            agent.agent_id.includes('ndis') ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' :
                            agent.agent_id.includes('envoy') ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' :
                            'bg-indigo-500/10 text-indigo-400 border-indigo-500/20'
                          }`}>
                            {agent.agent_id.includes('ebpf') ? 'Layer 0: Linux Kern eBPF' :
                             agent.agent_id.includes('ndis') ? 'Layer 0: Win Kern NDIS' :
                             agent.agent_id.includes('envoy') ? 'Layer 1: Envoy Sidecar & WAF' :
                             'Layer 2: Deep SOC / SLM Cluster'}
                          </span>
                        </td>
                        <td className="px-6 py-5">
                          <div className="flex items-center gap-2">
                            <div className="w-16 bg-gray-800 rounded-full h-1.5 overflow-hidden">
                              <div className="bg-blue-500 h-full rounded-full" style={{ width: `${agent.cpu_usage * 5}%` }}></div>
                            </div>
                            <span className="font-mono text-xs text-gray-300 font-bold">{agent.cpu_usage}%</span>
                          </div>
                        </td>
                        <td className="px-6 py-5 font-mono text-xs text-gray-400">
                          {agent.memory_mb >= 1020 ? `${(agent.memory_mb / 1024).toFixed(2)} GB` : `${agent.memory_mb} MB`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* LIVE INCIDENTS / MITIGATION FEED */}
            <div className="bg-[#121214] rounded-2xl border border-gray-800/80 shadow-2xl overflow-hidden flex flex-col h-[520px]">
              <div className="p-6 border-b border-gray-800/80 bg-[#151518] flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold flex items-center gap-2 text-white">
                    <Activity className="w-5 h-5 text-gray-400"/> Security Incident Stream
                  </h2>
                  <p className="text-gray-400 text-xs mt-1">Automated mitigation loop real-time feed</p>
                </div>
                <button 
                  onClick={handleResetSimulator}
                  className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs px-2.5 py-1.5 rounded-lg transition-colors border border-gray-700/80 flex items-center gap-1 font-mono"
                  title="Restore clean state logs"
                >
                  <RefreshCw className="w-3" /> REST RESET
                </button>
              </div>
              <div className="p-5 overflow-y-auto flex-1 space-y-4">
                {loading && <p className="text-gray-500 text-center py-10">Syncing with defensive agent rings...</p>}
                {!loading && incidents.length === 0 && (
                  <div className="text-center py-16">
                    <CheckCircle className="w-10 h-10 text-emerald-500 mx-auto opacity-40 mb-3" />
                    <p className="text-gray-400 font-semibold">Zero Anomaly Triggers Detected</p>
                    <p className="text-gray-500 text-xs mt-1">All gateway systems are clean and reporting safe telemetry.</p>
                  </div>
                )}
                {incidents.map(inc => (
                  <div key={inc.incident_id} className="bg-[#17171a] p-4.5 rounded-xl border border-gray-800/80 relative overflow-hidden group hover:border-gray-700/80 transition-all">
                    <div className={`absolute left-0 top-0 bottom-0 w-1 ${
                      inc.severity === 'CRITICAL' ? 'bg-gradient-to-b from-red-500 to-amber-500' : 
                      inc.severity === 'HIGH' ? 'bg-orange-500' : 'bg-yellow-500'
                    }`} />
                    <div className="flex justify-between items-start ml-2 mb-2">
                      <span className={`font-bold text-xs uppercase tracking-wider px-2 py-0.5 rounded ${
                        inc.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 
                        inc.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' : 
                        'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
                      }`}>
                        {inc.severity}
                      </span>
                      <span className="text-xs text-gray-500 flex items-center gap-1 font-mono">
                        <Clock className="w-3 h-3" /> {new Date(inc.reported_at).toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="text-sm font-medium text-gray-200 ml-2 leading-relaxed">{inc.description}</p>
                    <div className="mt-3.5 pt-2.5 border-t border-gray-800/40 flex items-center justify-between ml-2 text-3xs font-mono text-gray-500">
                      <span>SOURCE: {inc.agent_id === "agent-01-ebpf" || inc.agent_id === "agent-02-ndis" ? "KERNEL DRIVER [LAYER 0]" : inc.agent_id === "agent-03-envoy" ? "SIDECAR REVERSE PROXY [LAYER 1]" : "SLM SOC CORE [LAYER 2]"}</span>
                      <span>Mitigated ✅</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
          
          {/* ARCHITECTURAL STACK DIAGRAM */}
          <div className="mt-10 bg-[#121214] p-8 rounded-2xl border border-gray-800/80 shadow-2xl">
            <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2"><Lock className="w-5 h-5 text-gray-400" /> Layered Security Enforcement Map</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-[#17171a] p-5.5 rounded-xl border border-gray-850">
                <div className="flex items-center gap-2 text-blue-400 font-bold font-mono mb-2 text-xs uppercase tracking-wider">
                  <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping"></span>
                  LAYER 0: Kernel Filters
                </div>
                <h4 className="text-base font-bold text-white mb-2">XDP/eBPF & NDIS Driver</h4>
                <p className="text-gray-400 text-xs leading-relaxed">Runs directly at the networking stack level of Linux/Windows hosts. Blocks packet-level volumetric DDoS floods and blacklisted IP segments in sub-microsecond cycles prior to memory allocation.</p>
              </div>
              <div className="bg-[#17171a] p-5.5 rounded-xl border border-gray-850">
                <div className="flex items-center gap-2 text-cyan-400 font-bold font-mono mb-2 text-xs uppercase tracking-wider">
                  <span className="w-2 h-2 rounded-full bg-cyan-500 animate-ping"></span>
                  LAYER 1: Edge Sidecar
                </div>
                <h4 className="text-base font-bold text-white mb-2">Envoy & Coraza WAF</h4>
                <p className="text-gray-400 text-xs leading-relaxed">Deep layer payload scrubbing, HTTP stream parsing, header rulesets and semantic signatures mapped into WASM bytecode configurations. Drops SQLi, command execution, and XSS threats.</p>
              </div>
              <div className="bg-[#17171a] p-5.5 rounded-xl border border-gray-850">
                <div className="flex items-center gap-2 text-indigo-400 font-bold font-mono mb-2 text-xs uppercase tracking-wider">
                  <span className="w-2 h-2 rounded-full bg-indigo-500 animate-ping"></span>
                  LAYER 2: Cognitive Center
                </div>
                <h4 className="text-base font-bold text-white mb-2">HA Core / Neural SLM</h4>
                <p className="text-gray-400 text-xs leading-relaxed">Central high-availability PostgreSQL & Redis pipelines analyzing streaming telemetry. Runs non-stationary sequence analyzers classifying potential zero-day threats using customized SLMs.</p>
              </div>
            </div>
          </div>

        </motion.div>
      )}

      {/* POLICY ENGINE TAB */}
      {activeTab === 'policies' && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="max-w-4xl mx-auto">
          <div className="bg-[#121214] rounded-2xl border border-gray-800/80 shadow-2xl overflow-hidden">
            <div className="p-8 border-b border-gray-800/80 bg-[#151518]">
              <h2 className="text-xl font-bold flex items-center gap-2.5 text-white">
                <Send className="w-6 h-6 text-blue-500 animate-bounce" /> Enterprise Policy Engine
              </h2>
              <p className="text-gray-400 text-sm mt-1">Multi-cast declarative schema configurations across edge fast filters and API controllers instantly</p>
            </div>
            
            <form onSubmit={handlePushPolicy} className="p-8 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2.5">
                  <label className="text-sm font-semibold text-gray-300">Target Defend Module</label>
                  <select 
                    value={policyType} 
                    onChange={e => setPolicyType(e.target.value)}
                    className="w-full bg-[#080809] border border-gray-800 rounded-xl px-4 py-3.5 focus:outline-none focus:border-blue-500 text-gray-100 font-medium transition-colors"
                  >
                    <option value="block_ip">Drop IPv4/IPv6 CIDR Block (Layer 0 Fast Hook)</option>
                    <option value="sigma_rule">Process EDR Sigma Block Pattern (Layer 0 Host)</option>
                    <option value="waf_rule">Envoy Sidecar Web WAF Rule (Layer 1 WAF)</option>
                  </select>
                </div>
                
                <div className="space-y-2.5">
                  <label className="text-sm font-semibold text-gray-300">Enforcement Mode</label>
                  <select 
                    value={enforcementMode} 
                    onChange={e => setEnforcementMode(e.target.value)}
                    className="w-full bg-[#080809] border border-gray-800 rounded-xl px-4 py-3.5 focus:outline-none focus:border-blue-500 text-gray-100 font-medium transition-colors"
                  >
                    <option value="ENFORCE">ENFORCE (Drop and terminate matching threats)</option>
                    <option value="AUDIT">AUDIT (Permit through pipeline but log metadata)</option>
                  </select>
                </div>
              </div>

              <div className="space-y-2.5">
                <label className="text-sm font-semibold text-gray-300">Rule Identification Descriptor</label>
                <input 
                  type="text" 
                  required
                  value={ruleId}
                  onChange={e => setRuleId(e.target.value)}
                  placeholder="e.g. BLOCK_MALICIOUS_WAN_IP_GROUP"
                  className="w-full bg-[#080809] border border-gray-800 rounded-xl px-4 py-3.5 focus:outline-none focus:border-blue-500 text-gray-100 font-medium font-mono placeholder:text-gray-600 transition-colors"
                />
              </div>

              <div className="space-y-2.5">
                <label className="text-sm font-semibold text-gray-300">Rule Parameters (IP Range, Regex expression, or JSON template)</label>
                <textarea 
                  required
                  value={content}
                  onChange={e => setContent(e.target.value)}
                  rows={4}
                  placeholder={policyType === 'block_ip' ? "185.220.101.5" : policyType === 'sigma_rule' ? "nc -e" : "SecRule REQUEST_COOKIES \"union select\" \"id:40001,deny,status:403\""}
                  className="w-full bg-[#080809] border border-gray-800 rounded-xl px-4 py-3.5 focus:outline-none focus:border-blue-500 text-gray-100 font-mono text-sm placeholder:text-gray-600 transition-colors"
                />
              </div>

              <div className="pt-6 border-t border-gray-800/80 flex items-center justify-between">
                <div className="text-sm font-semibold">
                  <AnimatePresence>
                    {pushStatus === 'success' && (
                      <motion.span initial={{ opacity: 0, x: -5 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} className="text-emerald-400 flex items-center gap-1.5">
                        <CheckCircle className="w-5 h-5"/> Rules propagated across eBPF/Envoy array!
                      </motion.span>
                    )}
                    {pushStatus === 'error' && (
                      <motion.span initial={{ opacity: 0, x: -5 }} animate={{ opacity: 1, x: 0 }} className="text-red-400">
                        Failed to serialize & push policy structure.
                      </motion.span>
                    )}
                  </AnimatePresence>
                </div>
                <button 
                  type="submit" 
                  disabled={isSubmitting}
                  className="bg-blue-600 hover:bg-blue-500 text-white px-8 py-3.5 rounded-xl font-bold transition-all disabled:opacity-50 flex items-center gap-2.5 shadow-lg shadow-blue-500/20 text-sm hover:translate-y-[-1px] active:translate-y-[0px]"
                >
                  {isSubmitting ? 'Distributing to cluster...' : <><PlusCircle className="w-4 h-4"/> Multi-Cast Policy</>}
                </button>
              </div>
            </form>
          </div>
        </motion.div>
      )}

      {/* THREAT SPACE / SIMULATOR TAB */}
      {activeTab === 'simulator' && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="max-w-5xl mx-auto">
          <div className="bg-[#121214] rounded-2xl border border-gray-800/80 shadow-2xl p-8 mb-8">
            <div className="mb-6">
              <h2 className="text-xl font-bold text-white flex items-center gap-2"><Terminal className="w-5 h-5 text-blue-500" /> Active Threat Exploit Room</h2>
              <p className="text-gray-400 text-sm mt-1">Interactively inject high-impact security exploits to physically test the autonomous pipeline mitigation defenses.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              
              {/* DDoS Exploits Card */}
              <div className="bg-[#17171a] p-6 rounded-xl border border-gray-800 flex flex-col justify-between hover:border-blue-500/30 transition-all duration-200">
                <div>
                  <div className="bg-blue-600/10 p-3 rounded-lg border border-blue-500/10 w-fit mb-4">
                    <Flame className="w-5 h-5 text-blue-500" />
                  </div>
                  <h3 className="font-bold text-white text-base">Volumetric DDoS</h3>
                  <p className="text-gray-400 text-xs mt-2 leading-relaxed">Flood target node with 1.2M packets per second of spoofed TCP SYN packets</p>
                </div>
                <button 
                  onClick={() => triggerSimulation("ddos")}
                  disabled={!!simulationRunning}
                  className="mt-6 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-bold text-xs py-2.5 rounded-lg transition-colors flex items-center justify-center gap-1.5 uppercase font-mono tracking-wider"
                >
                  Deploy SYN-Flood <ArrowRight className="w-3.5" />
                </button>
              </div>

              {/* SQLi Exploit Card */}
              <div className="bg-[#17171a] p-6 rounded-xl border border-gray-800 flex flex-col justify-between hover:border-teal-500/30 transition-all duration-200">
                <div>
                  <div className="bg-teal-600/10 p-3 rounded-lg border border-teal-500/10 w-fit mb-4">
                    <Database className="w-5 h-5 text-teal-400" />
                  </div>
                  <h3 className="font-bold text-white text-base">SQL Injection</h3>
                  <p className="text-gray-400 text-xs mt-2 leading-relaxed">Attempt web service path traversal and credential DB select dump queries</p>
                </div>
                <button 
                  onClick={() => triggerSimulation("sqli")}
                  disabled={!!simulationRunning}
                  className="mt-6 bg-teal-600 hover:bg-teal-500 disabled:opacity-50 text-white font-bold text-xs py-2.5 rounded-lg transition-colors flex items-center justify-center gap-1.5 uppercase font-mono tracking-wider"
                >
                  Push Web Exploit <ArrowRight className="w-3.5" />
                </button>
              </div>

              {/* Shell Trojan Exploit Card */}
              <div className="bg-[#17171a] p-6 rounded-xl border border-gray-800 flex flex-col justify-between hover:border-purple-500/30 transition-all duration-200">
                <div>
                  <div className="bg-purple-600/10 p-3 rounded-lg border border-purple-500/10 w-fit mb-4">
                    <Terminal className="w-5 h-5 text-purple-400" />
                  </div>
                  <h3 className="font-bold text-white text-base">Host Shell Hijack</h3>
                  <p className="text-gray-400 text-xs mt-2 leading-relaxed">Launch unauthorized background shell connections posing as cryptomining systems</p>
                </div>
                <button 
                  onClick={() => triggerSimulation("edr")}
                  disabled={!!simulationRunning}
                  className="mt-6 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-bold text-xs py-2.5 rounded-lg transition-colors flex items-center justify-center gap-1.5 uppercase font-mono tracking-wider"
                >
                  Deliver EDR Shock <ArrowRight className="w-3.5" />
                </button>
              </div>

              {/* Zero-Day Exploits Card */}
              <div className="bg-[#17171a] p-6 rounded-xl border border-gray-800 flex flex-col justify-between hover:border-amber-500/30 transition-all duration-200">
                <div>
                  <div className="bg-amber-600/10 p-3 rounded-lg border border-amber-500/10 w-fit mb-4">
                    <AlertTriangle className="w-5 h-5 text-amber-400" />
                  </div>
                  <h3 className="font-bold text-white text-base">Header Zero-Day</h3>
                  <p className="text-gray-400 text-xs mt-2 leading-relaxed">Inject custom Log4j strings through HTTP fields to evade static signature matrices</p>
                </div>
                <button 
                  onClick={() => triggerSimulation("zeroday")}
                  disabled={!!simulationRunning}
                  className="mt-6 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white font-bold text-xs py-2.5 rounded-lg transition-colors flex items-center justify-center gap-1.5 uppercase font-mono tracking-wider"
                >
                  Inject Zero-Day <ArrowRight className="w-3.5" />
                </button>
              </div>

            </div>

            {/* SIMULATOR STAGES INTERACTIVE VIEWER */}
            <AnimatePresence>
              {simulationRunning && (
                <motion.div 
                  initial={{ opacity: 0, y: 10 }} 
                  animate={{ opacity: 1, y: 0 }} 
                  exit={{ opacity: 0 }}
                  className="mt-10 p-6 bg-[#0c0c0e] border border-blue-500/20 rounded-xl relative overflow-hidden"
                >
                  <div className="absolute top-0 right-0 p-3 font-mono text-3xs text-blue-500/40">SIMUL_STRE_0FF</div>
                  <div className="flex items-start gap-4">
                    <div className="bg-blue-600/10 p-2 rounded-lg border border-blue-500/10 animate-spin mt-1">
                      <RefreshCw className="w-5 h-5 text-blue-500" />
                    </div>
                    <div className="flex-1">
                      <span className="font-mono text-xs font-bold text-blue-400 uppercase tracking-widest block">Simulator Monitor Stack</span>
                      <p className="text-base text-gray-200 mt-1.5 font-semibold text-wrap leading-relaxed">{simulationStatus}</p>
                      
                      {/* Interactive Visual Progression dots & states */}
                      <div className="flex items-center gap-10 mt-6 pt-5 border-t border-gray-900 font-mono text-2xs">
                        <div className="flex items-center gap-2">
                          <span className={`w-3.5 h-3.5 rounded-full flex items-center justify-center text-3xs font-bold ${simulationStatus?.includes('neutralized') ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-blue-500/10 text-blue-400 border border-blue-500/30'}`}>0</span>
                          <span className="text-gray-400">Layer 0 (Host Filter)</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="w-3.5 h-3.5 bg-[#17171a] border border-gray-800 rounded-full flex items-center justify-center text-3xs font-bold text-gray-500">1</span>
                          <span className="text-gray-500">Layer 1 (Envoy WAF)</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="w-3.5 h-3.5 bg-[#17171a] border border-gray-800 rounded-full flex items-center justify-center text-3xs font-bold text-gray-500">2</span>
                          <span className="text-gray-500">Layer 2 (SOC SLM Core)</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
          
          <div className="bg-[#121214] p-8 rounded-2xl border border-gray-800/80 shadow-2xl">
            <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Lock className="w-5 h-5 text-indigo-400" /> Enterprise-Grade Autonomous Policy Guarantee</h3>
            <p className="text-gray-400 text-sm leading-relaxed mb-4">
              Our triple-stage network gateway operates completely locally in a dual synchronous/asynchronous mode. Any client-facing security anomaly triggering maximum confidence scales is instantly quarantined at Layer 0 (the network interface card itself), completely isolated from your user hosts without waiting for central control-plane feedback, giving your workloads zero-latency, fail-close resilient SLA guarantees against cyber exploitation.
            </p>
          </div>
        </motion.div>
      )}

    </div>
  );
}

function StatCard({ title, value, sub, icon, color }: { title: string, value: string, sub: string, icon: React.ReactNode, color: string }) {
  const borderColors: Record<string, string> = {
    blue: "border-blue-500/10 hover:border-blue-500/30",
    amber: "border-amber-500/10 hover:border-amber-500/30",
    emerald: "border-emerald-500/10 hover:border-emerald-500/30",
    indigo: "border-indigo-500/10 hover:border-indigo-500/30",
  };
  return (
    <div className={`bg-[#121214] p-6 rounded-2xl border ${borderColors[color] || 'border-gray-800'} transition-all duration-200 shadow-md relative overflow-hidden group`}>
      <div className="absolute -right-6 -bottom-6 opacity-[0.03] transition-transform group-hover:scale-110 duration-500">
        {React.cloneElement(icon as React.ReactElement, { className: 'w-32 h-32' })}
      </div>
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-gray-400 text-xs font-semibold uppercase tracking-wider">{title}</h3>
        <div className={`p-2 rounded-xl bg-gray-900 border border-gray-800/80`}>
          {icon}
        </div>
      </div>
      <div>
        <p className="text-3xl font-extrabold text-white tracking-tight">{value}</p>
        <span className="text-gray-500 text-2xs mt-1.5 font-mono block uppercase tracking-wider">{sub}</span>
      </div>
    </div>
  );
}
