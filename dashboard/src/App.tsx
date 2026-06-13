import React, { useState, useEffect, useCallback } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface Agent {
  agent_id: string;
  hostname: string;
  ip_address: string;
  status: 'ACTIVE' | 'DEGRADED' | 'OFFLINE';
  cpu_usage: number;
  memory_mb: number;
  last_heartbeat: string;
}

interface Alert {
  id: string;
  timestamp: string;
  source: string;
  rule_name: string;
  threat_level: 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown';
  description: string;
  src_ip?: string;
  dst_ip?: string;
  soar_actions_taken: string[];
}

interface Stats {
  packets_processed: number;
  packets_dropped: number;
  active_flows: number;
  total_alerts: number;
  ioc_count: number;
  ws_clients: number;
}

interface AuthState {
  token: string | null;
  role: string | null;
  error: string | null;
}

// ─── Config ───────────────────────────────────────────────────────────────────

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080';

function apiHeaders(token: string): HeadersInit {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
  };
}

// ─── Login Screen ─────────────────────────────────────────────────────────────

function LoginScreen({
  onLogin,
}: {
  onLogin: (token: string, role: string) => void;
}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        const msg = res.status === 401 ? 'Invalid credentials' : `Error ${res.status}`;
        throw new Error(msg);
      }
      const data = await res.json();
      onLogin(data.token, data.role);
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <div className="bg-gray-800 rounded-xl p-8 w-full max-w-sm shadow-2xl border border-gray-700">
        <h1 className="text-2xl font-bold text-blue-400 mb-2">🛡️ Thor Firewall</h1>
        <p className="text-gray-400 text-sm mb-6">Authenticate to access the control plane</p>
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={e => setUsername(e.target.value)}
            required
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
          />
          {error && (
            <p className="text-red-400 text-sm">{error}</p>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-semibold py-2 rounded transition"
          >
            {loading ? 'Authenticating...' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

function Dashboard({ token, role, onLogout }: { token: string; role: string; onLogout: () => void }) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [apiError, setApiError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, alertsRes] = await Promise.all([
        fetch(`${API_URL}/api/v1/stats`, { headers: apiHeaders(token) }),
        fetch(`${API_URL}/api/v1/alerts/recent`, { headers: apiHeaders(token) }),
      ]);

      if (statsRes.status === 401 || alertsRes.status === 401) {
        onLogout();
        return;
      }

      if (!statsRes.ok || !alertsRes.ok) {
        throw new Error(`API error: ${statsRes.status}`);
      }

      const [statsData, alertsData] = await Promise.all([
        statsRes.json(),
        alertsRes.json(),
      ]);

      setStats(statsData);
      setAlerts(alertsData);
      setApiError(null);
      setLastUpdated(new Date());
    } catch (err: any) {
      setApiError(err.message || 'Failed to fetch data');
    }
  }, [token, onLogout]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const criticalCount = alerts.filter(a => a.threat_level === 'Critical').length;
  const highCount = alerts.filter(a => a.threat_level === 'High').length;

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 font-sans">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-blue-400">🛡️ Thor Control Plane</h1>
          <p className="text-gray-500 text-xs mt-0.5">
            {lastUpdated
              ? `Last updated: ${lastUpdated.toLocaleTimeString()}`
              : 'Connecting to API...'}
          </p>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-xs text-gray-400 bg-gray-700 px-3 py-1 rounded-full">
            {role}
          </span>
          <button
            onClick={onLogout}
            className="text-xs text-gray-400 hover:text-white border border-gray-600 px-3 py-1 rounded transition"
          >
            Logout
          </button>
        </div>
      </header>

      <main className="p-6 space-y-6">
        {/* API Error Banner */}
        {apiError && (
          <div className="bg-red-900/50 border border-red-700 rounded-lg p-3 text-red-300 text-sm">
            ⚠️ API Error: {apiError} — retrying...
          </div>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <StatCard title="Packets In" value={fmt(stats?.packets_processed)} color="blue" />
          <StatCard title="Dropped" value={fmt(stats?.packets_dropped)} color="red" />
          <StatCard title="Active Flows" value={fmt(stats?.active_flows)} color="green" />
          <StatCard title="Total Alerts" value={fmt(stats?.total_alerts)} color="yellow" />
          <StatCard title="IOC Entries" value={fmt(stats?.ioc_count)} color="purple" />
          <StatCard title="WS Clients" value={fmt(stats?.ws_clients)} color="gray" />
        </div>

        {/* Alerts */}
        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Live Threat Feed</h2>
            <div className="flex gap-2 text-xs">
              {criticalCount > 0 && (
                <span className="bg-red-900 text-red-300 px-2 py-1 rounded font-bold">
                  {criticalCount} CRITICAL
                </span>
              )}
              {highCount > 0 && (
                <span className="bg-orange-900 text-orange-300 px-2 py-1 rounded">
                  {highCount} HIGH
                </span>
              )}
            </div>
          </div>

          {alerts.length === 0 ? (
            <p className="text-gray-500 text-sm py-8 text-center">
              {stats ? '✅ No active threats detected' : 'Loading...'}
            </p>
          ) : (
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {alerts.map(alert => (
                <AlertCard key={alert.id} alert={alert} />
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

// ─── Alert Card ───────────────────────────────────────────────────────────────

function AlertCard({ alert }: { alert: Alert }) {
  const borderColor: Record<string, string> = {
    Critical: 'border-red-500',
    High: 'border-orange-500',
    Medium: 'border-yellow-500',
    Low: 'border-blue-500',
    Unknown: 'border-gray-500',
  };
  const levelColor: Record<string, string> = {
    Critical: 'text-red-400',
    High: 'text-orange-400',
    Medium: 'text-yellow-400',
    Low: 'text-blue-400',
    Unknown: 'text-gray-400',
  };

  return (
    <div
      className={`bg-gray-900 p-4 rounded-lg border-l-4 ${borderColor[alert.threat_level] || 'border-gray-500'}`}
    >
      <div className="flex justify-between items-start">
        <span className={`font-bold text-sm ${levelColor[alert.threat_level]}`}>
          {alert.threat_level}
        </span>
        <span className="text-xs text-gray-500">
          {new Date(alert.timestamp).toLocaleTimeString()}
        </span>
      </div>
      <p className="text-white font-medium mt-1 text-sm">{alert.rule_name}</p>
      <p className="text-gray-400 text-xs mt-1">{alert.description}</p>
      <div className="flex gap-4 mt-2 text-xs text-gray-500">
        {alert.src_ip && <span>src: {alert.src_ip}</span>}
        {alert.dst_ip && <span>dst: {alert.dst_ip}</span>}
        <span>src: {alert.source}</span>
      </div>
      {alert.soar_actions_taken.length > 0 && (
        <div className="flex gap-1 mt-2 flex-wrap">
          {alert.soar_actions_taken.map((a, i) => (
            <span key={i} className="bg-green-900/50 text-green-400 text-xs px-2 py-0.5 rounded">
              {a}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function StatCard({
  title,
  value,
  color,
}: {
  title: string;
  value: string;
  color: string;
}) {
  const colors: Record<string, string> = {
    blue: 'text-blue-400',
    red: 'text-red-400',
    green: 'text-green-400',
    yellow: 'text-yellow-400',
    purple: 'text-purple-400',
    gray: 'text-gray-400',
  };
  return (
    <div className="bg-gray-800 p-4 rounded-xl border border-gray-700">
      <p className="text-gray-500 text-xs uppercase tracking-wide">{title}</p>
      <p className={`text-2xl font-bold mt-1 ${colors[color] || 'text-white'}`}>{value}</p>
    </div>
  );
}

function fmt(n?: number | null): string {
  if (n == null) return '—';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

// ─── Root App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [auth, setAuth] = useState<AuthState>(() => {
    const token = sessionStorage.getItem('thor_token');
    const role = sessionStorage.getItem('thor_role');
    return { token, role, error: null };
  });

  const handleLogin = (token: string, role: string) => {
    sessionStorage.setItem('thor_token', token);
    sessionStorage.setItem('thor_role', role);
    setAuth({ token, role, error: null });
  };

  const handleLogout = () => {
    sessionStorage.removeItem('thor_token');
    sessionStorage.removeItem('thor_role');
    setAuth({ token: null, role: null, error: null });
  };

  if (!auth.token || !auth.role) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return (
    <Dashboard token={auth.token} role={auth.role} onLogout={handleLogout} />
  );
}
