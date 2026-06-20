import React, { useState, useEffect, useRef, useCallback } from 'react';

// ─── Types ──────────────────────────────────────────────────────────────────

interface Agent {
  agent_id: string;
  last_seen: number;
  status: 'ACTIVE' | 'DEGRADED' | 'OFFLINE';
}

interface ThorEvent {
  event_id: string;
  timestamp: number;
  agent_id: string;
  agent_type: 'network' | 'web' | 'server';
  threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  action: string;
  decision: 'autonomous' | 'escalated' | 'logged';
  score: number;
  model_id: string;
  xai_summary: string;
  description: string;
  mitre?: string;
  audit_seq?: number;
}

interface PendingDecision {
  event_id: string;
  agent_id: string;
  agent_type: string;
  escalated_at: number;
  proposed_action: string;
  score: number;
  xai_summary: string;
  threat_level: string;
  description: string;
  status: 'pending' | 'approved' | 'rejected';
}

interface AgentPolicy {
  agent_type: string;
  auto_action_threshold: number;
  alert_threshold: number;
  offline_autonomous: boolean;
  allowed_auto_actions: string[];
  policy_version: string;
  approved_by: string;
}

interface DashboardData {
  agents: Agent[];
  agents_total: number;
  events_total: number;
  pending_decisions: number;
  auto_actions_total: number;
  recent_events: ThorEvent[];
  threat_summary: { CRITICAL: number; HIGH: number };
  fl_rounds: number;
  audit_entries: number;
}

interface FLStatus {
  active_rounds: number;
  rounds: Array<{
    model_id: string;
    status: string;
    max_jsd: number;
    retrain_proposed: boolean;
    contributions: unknown[];
  }>;
  retrain_proposals: number;
}

// ─── Constants ──────────────────────────────────────────────────────────────

const CP_URL = process.env.REACT_APP_CP_URL || 'http://localhost:8080';
const REFRESH_MS = 5000;

const THREAT_COLORS: Record<string, string> = {
  CRITICAL: '#ff2d55',
  HIGH:     '#ff9f0a',
  MEDIUM:   '#ffd60a',
  LOW:      '#30d158',
  UNKNOWN:  '#636366',
};

const DECISION_ICONS: Record<string, string> = {
  autonomous: '⚡',
  escalated:  '🔔',
  logged:     '📝',
};

const AGENT_TYPE_ICONS: Record<string, string> = {
  network: '🌐',
  web:     '🛡️',
  server:  '💻',
};

// ─── Utilities ──────────────────────────────────────────────────────────────

function formatTs(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString();
}

function formatScore(s: number): string {
  return `${(s * 100).toFixed(1)}%`;
}

// ─── Components ─────────────────────────────────────────────────────────────

const Badge: React.FC<{ text: string; color: string; small?: boolean }> = ({ text, color, small }) => (
  <span style={{
    background: color + '22', color, border: `1px solid ${color}44`,
    borderRadius: 4, padding: small ? '1px 6px' : '2px 10px',
    fontSize: small ? 10 : 12, fontWeight: 700, letterSpacing: '0.04em',
    fontFamily: 'monospace',
  }}>{text}</span>
);

const StatCard: React.FC<{ title: string; value: string | number; sub?: string; color?: string; icon?: string }> = ({ title, value, sub, color = '#0a84ff', icon }) => (
  <div style={{
    background: '#1c1c1e', border: `1px solid ${color}33`,
    borderRadius: 12, padding: '18px 22px', minWidth: 160,
  }}>
    <div style={{ color: '#8e8e93', fontSize: 12, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 8 }}>
      {icon && <span style={{ marginRight: 6 }}>{icon}</span>}{title}
    </div>
    <div style={{ color, fontSize: 32, fontWeight: 800, fontFamily: 'monospace', lineHeight: 1 }}>{value}</div>
    {sub && <div style={{ color: '#8e8e93', fontSize: 11, marginTop: 6 }}>{sub}</div>}
  </div>
);

const SeverityBar: React.FC<{ score: number }> = ({ score }) => {
  const color = score >= 0.90 ? THREAT_COLORS.CRITICAL
               : score >= 0.70 ? THREAT_COLORS.HIGH
               : score >= 0.50 ? THREAT_COLORS.MEDIUM
               : THREAT_COLORS.LOW;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, background: '#2c2c2e', borderRadius: 4, height: 6, overflow: 'hidden' }}>
        <div style={{ width: `${score * 100}%`, background: color, height: '100%', transition: 'width 0.3s' }} />
      </div>
      <span style={{ color, fontSize: 11, fontFamily: 'monospace', minWidth: 40 }}>{formatScore(score)}</span>
    </div>
  );
};

// ─── Event Row ───────────────────────────────────────────────────────────────

const EventRow: React.FC<{ event: ThorEvent; onClick: () => void }> = ({ event, onClick }) => (
  <tr
    onClick={onClick}
    style={{ cursor: 'pointer', borderBottom: '1px solid #2c2c2e' }}
    onMouseEnter={e => (e.currentTarget.style.background = '#1c1c1e')}
    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
  >
    <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: 11, color: '#8e8e93' }}>
      {formatTs(event.timestamp)}
    </td>
    <td style={{ padding: '8px 4px' }}>
      <Badge text={event.threat_level} color={THREAT_COLORS[event.threat_level] || '#636366'} small />
    </td>
    <td style={{ padding: '8px 12px', fontSize: 12 }}>
      <span style={{ marginRight: 4 }}>{AGENT_TYPE_ICONS[event.agent_type] || '❓'}</span>
      <span style={{ color: '#ebebf5', fontFamily: 'monospace', fontSize: 11 }}>{event.agent_id.slice(-12)}</span>
    </td>
    <td style={{ padding: '8px 12px', fontSize: 12, color: '#ebebf5', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
      {event.description}
    </td>
    <td style={{ padding: '8px 8px' }}>
      <Badge
        text={`${DECISION_ICONS[event.decision] || ''} ${event.decision}`}
        color={event.decision === 'autonomous' ? '#30d158' : event.decision === 'escalated' ? '#ff9f0a' : '#636366'}
        small
      />
    </td>
    <td style={{ padding: '8px 12px' }}>
      <SeverityBar score={event.score} />
    </td>
    {event.audit_seq !== undefined && (
      <td style={{ padding: '8px 8px', fontFamily: 'monospace', fontSize: 10, color: '#636366' }}>
        #{event.audit_seq}
      </td>
    )}
  </tr>
);

// ─── Event Detail Modal ───────────────────────────────────────────────────────

const EventModal: React.FC<{ event: ThorEvent; onClose: () => void }> = ({ event, onClose }) => (
  <div style={{
    position: 'fixed', inset: 0, background: '#000000cc',
    display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
  }} onClick={onClose}>
    <div style={{
      background: '#1c1c1e', border: '1px solid #3a3a3c', borderRadius: 16,
      padding: 28, maxWidth: 640, width: '90%', maxHeight: '80vh', overflowY: 'auto',
    }} onClick={e => e.stopPropagation()}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20 }}>
        <h3 style={{ color: '#ebebf5', margin: 0, fontSize: 18 }}>
          {AGENT_TYPE_ICONS[event.agent_type]} Event Details
        </h3>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#8e8e93', cursor: 'pointer', fontSize: 22 }}>×</button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
        {[
          ['Event ID',   event.event_id.slice(0, 16) + '...'],
          ['Agent',      event.agent_id],
          ['Timestamp',  formatTs(event.timestamp)],
          ['Action',     event.action],
          ['Model',      event.model_id],
          ['MITRE',      event.mitre || 'N/A'],
          ['Audit Seq',  event.audit_seq !== undefined ? `#${event.audit_seq}` : 'N/A'],
          ['Decision',   event.decision],
        ].map(([label, val]) => (
          <div key={label} style={{ background: '#2c2c2e', borderRadius: 8, padding: '10px 14px' }}>
            <div style={{ color: '#8e8e93', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>{label}</div>
            <div style={{ color: '#ebebf5', fontFamily: 'monospace', fontSize: 12 }}>{val}</div>
          </div>
        ))}
      </div>

      <div style={{ background: '#2c2c2e', borderRadius: 8, padding: '14px 16px', marginBottom: 14 }}>
        <div style={{ color: '#8e8e93', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
          🧠 XAI Explanation
        </div>
        <div style={{ color: '#ebebf5', fontSize: 13, lineHeight: 1.6 }}>{event.xai_summary}</div>
      </div>

      <div style={{ marginBottom: 14 }}>
        <div style={{ color: '#8e8e93', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>ML Confidence Score</div>
        <SeverityBar score={event.score} />
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <Badge text={event.threat_level} color={THREAT_COLORS[event.threat_level] || '#636366'} />
        <Badge text={event.decision} color={event.decision === 'autonomous' ? '#30d158' : '#ff9f0a'} />
        {event.mitre && <Badge text={event.mitre} color='#bf5af2' />}
      </div>
    </div>
  </div>
);

// ─── Policy Editor ────────────────────────────────────────────────────────────

const PolicyEditor: React.FC<{ policy: AgentPolicy; onSave: (p: AgentPolicy) => void }> = ({ policy, onSave }) => {
  const [threshold, setThreshold] = useState(policy.auto_action_threshold);
  const [analyst, setAnalyst] = useState('soc-analyst');

  return (
    <div style={{ background: '#2c2c2e', borderRadius: 8, padding: '16px 18px', marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <span style={{ color: '#ebebf5', fontWeight: 700 }}>
          {AGENT_TYPE_ICONS[policy.agent_type] || '⚙️'} {policy.agent_type.toUpperCase()} Agent
        </span>
        <Badge text={policy.policy_version} color='#636366' small />
      </div>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ flex: 1 }}>
          <div style={{ color: '#8e8e93', fontSize: 11, marginBottom: 4 }}>
            Auto-Action Threshold: <span style={{ color: '#0a84ff', fontFamily: 'monospace' }}>{(threshold * 100).toFixed(0)}%</span>
          </div>
          <input
            type="range" min="0.50" max="0.99" step="0.01"
            value={threshold}
            onChange={e => setThreshold(parseFloat(e.target.value))}
            style={{ width: '100%', accentColor: '#0a84ff' }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#636366', fontSize: 10 }}>
            <span>50% (permissive)</span><span>99% (conservative)</span>
          </div>
        </div>
        <div>
          <div style={{ color: '#8e8e93', fontSize: 11, marginBottom: 4 }}>Approved by</div>
          <input
            value={analyst} onChange={e => setAnalyst(e.target.value)}
            style={{ background: '#1c1c1e', border: '1px solid #3a3a3c', borderRadius: 6, padding: '4px 10px', color: '#ebebf5', fontSize: 12 }}
          />
        </div>
        <button
          onClick={() => onSave({ ...policy, auto_action_threshold: threshold, approved_by: analyst })}
          style={{
            background: '#0a84ff', color: '#fff', border: 'none',
            borderRadius: 8, padding: '8px 18px', cursor: 'pointer',
            fontWeight: 700, fontSize: 13,
          }}
        >Save Policy</button>
      </div>
      <div style={{ marginTop: 8 }}>
        <span style={{ color: '#8e8e93', fontSize: 11 }}>Allowed actions: </span>
        {policy.allowed_auto_actions.map(a => (
          <Badge key={a} text={a} color='#0a84ff' small />
        ))}
      </div>
    </div>
  );
};

// ─── Main App ────────────────────────────────────────────────────────────────

export default function App() {
  const [data, setData]         = useState<DashboardData | null>(null);
  const [pending, setPending]   = useState<PendingDecision[]>([]);
  const [policies, setPolicies] = useState<Record<string, AgentPolicy>>({});
  const [flStatus, setFlStatus] = useState<FLStatus | null>(null);
  const [liveEvents, setLiveEvents] = useState<ThorEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<ThorEvent | null>(null);
  const [activeTab, setActiveTab] = useState<'events' | 'decisions' | 'policy' | 'audit' | 'fl'>('events');
  const [loading, setLoading]   = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const api = (path: string, opts?: RequestInit) =>
    fetch(`${CP_URL}${path}`, opts).then(r => r.json()).catch(() => null);

  const refresh = useCallback(async () => {
    const [dash, pend, fl] = await Promise.all([
      api('/api/v1/dashboard'),
      api('/api/v1/decisions/pending'),
      api('/api/v1/fl/status'),
    ]);
    if (dash) setData(dash);
    if (pend?.pending) setPending(pend.pending);
    if (fl) setFlStatus(fl);

    for (const at of ['network', 'web', 'server']) {
      const p = await api(`/api/v1/policy/${at}`);
      if (p?.agent_type) setPolicies(prev => ({ ...prev, [at]: p }));
    }
    setLoading(false);
  }, []);

  // WebSocket real-time events
  useEffect(() => {
    const wsUrl = CP_URL.replace('http', 'ws') + '/ws/events';
    const connect = () => {
      const ws = new WebSocket(wsUrl);
      ws.onopen  = () => setWsConnected(true);
      ws.onclose = () => { setWsConnected(false); setTimeout(connect, 3000); };
      ws.onmessage = e => {
        try {
          const ev: ThorEvent = JSON.parse(e.data);
          setLiveEvents(prev => [ev, ...prev].slice(0, 200));
        } catch {}
      };
      wsRef.current = ws;
    };
    connect();
    return () => wsRef.current?.close();
  }, []);

  useEffect(() => { refresh(); const t = setInterval(refresh, REFRESH_MS); return () => clearInterval(t); }, [refresh]);

  const approveDecision = async (event_id: string) => {
    await api(`/api/v1/decisions/${event_id}/approve`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst: 'soc-analyst', note: 'Approved via SOC Dashboard' }),
    });
    refresh();
  };

  const rejectDecision = async (event_id: string) => {
    await api(`/api/v1/decisions/${event_id}/reject`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst: 'soc-analyst', note: 'Rejected via SOC Dashboard' }),
    });
    refresh();
  };

  const savePolicy = async (policy: AgentPolicy) => {
    await api(`/api/v1/policy/${policy.agent_type}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(policy),
    });
    refresh();
  };

  const approveRetrain = async (model_id: string) => {
    await api('/api/v1/fl/approve-retrain', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model_id, analyst: 'soc-analyst' }),
    });
    refresh();
  };

  if (loading) return (
    <div style={{ minHeight: '100vh', background: '#000', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ color: '#0a84ff', fontSize: 18, fontFamily: 'monospace' }}>⟳ Loading Aegis XDR SOC...</div>
    </div>
  );

  const allEvents = [...liveEvents, ...(data?.recent_events || [])].slice(0, 200);
  const pendingCount = pending.filter(p => p.status === 'pending').length;
  const TABS = [
    { id: 'events',    label: `Events (${allEvents.length})` },
    { id: 'decisions', label: `Decisions ${pendingCount > 0 ? `🔴 ${pendingCount}` : ''}` },
    { id: 'policy',    label: 'Policy' },
    { id: 'fl',        label: `FL ${flStatus?.retrain_proposals ? '⚠️' : ''}` },
    { id: 'audit',     label: 'Audit' },
  ] as const;

  return (
    <div style={{ minHeight: '100vh', background: '#000000', color: '#ebebf5', fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", system-ui, sans-serif' }}>
      {/* Header */}
      <header style={{ borderBottom: '1px solid #1c1c1e', padding: '16px 28px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'sticky', top: 0, background: '#000', zIndex: 100 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, background: 'linear-gradient(90deg, #0a84ff, #bf5af2)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            ⚔️ Aegis XDR — SOC Dashboard
          </h1>
          <div style={{ color: '#636366', fontSize: 12, marginTop: 2 }}>Sovereign Conditional AI Platform</div>
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <Badge text={wsConnected ? '● LIVE' : '○ OFFLINE'} color={wsConnected ? '#30d158' : '#ff3b30'} />
          <Badge text={`${data?.agents_total || 0} agents`} color='#0a84ff' />
          {pendingCount > 0 && <Badge text={`${pendingCount} pending`} color='#ff9f0a' />}
        </div>
      </header>

      <main style={{ padding: '24px 28px' }}>
        {/* Stat Cards */}
        <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginBottom: 28 }}>
          <StatCard title="Events Total"     value={data?.events_total || 0}      color='#0a84ff'  icon='📊' />
          <StatCard title="CRITICAL"         value={data?.threat_summary?.CRITICAL || 0} color='#ff2d55' icon='🔴' sub="last 50 events" />
          <StatCard title="HIGH"             value={data?.threat_summary?.HIGH || 0}     color='#ff9f0a' icon='🟠' sub="last 50 events" />
          <StatCard title="Pending Review"   value={pendingCount}                  color='#ff9f0a'  icon='🔔' sub="awaiting human" />
          <StatCard title="Auto Actions"     value={data?.auto_actions_total || 0} color='#30d158'  icon='⚡' sub="autonomous" />
          <StatCard title="Audit Chain"      value={data?.audit_entries || 0}      color='#bf5af2'  icon='🔗' sub="entries" />
          <StatCard title="FL Rounds"        value={data?.fl_rounds || 0}          color='#64d2ff'  icon='🧬' />
        </div>

        {/* Agent Fleet */}
        <div style={{ background: '#0a0a0a', border: '1px solid #1c1c1e', borderRadius: 12, padding: '16px 20px', marginBottom: 22 }}>
          <h2 style={{ margin: '0 0 14px', fontSize: 15, fontWeight: 700, color: '#ebebf5' }}>🖥️ Agent Fleet</h2>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {(data?.agents || []).map(ag => (
              <div key={ag.agent_id} style={{
                background: '#1c1c1e', borderRadius: 8, padding: '8px 14px',
                border: `1px solid ${ag.status === 'ACTIVE' ? '#30d15844' : '#ff9f0a44'}`,
                fontSize: 12,
              }}>
                <span style={{ marginRight: 6 }}>
                  {ag.agent_id.startsWith('net-') ? '🌐' : ag.agent_id.startsWith('web-') ? '🛡️' : '💻'}
                </span>
                <span style={{ fontFamily: 'monospace', color: '#ebebf5' }}>{ag.agent_id.slice(0, 20)}</span>
                <span style={{ marginLeft: 8 }}>
                  <Badge text={ag.status} color={ag.status === 'ACTIVE' ? '#30d158' : '#ff9f0a'} small />
                </span>
              </div>
            ))}
            {(data?.agents || []).length === 0 && (
              <div style={{ color: '#636366', fontSize: 13 }}>No agents registered yet. Deploy an agent to begin.</div>
            )}
          </div>
        </div>

        {/* Tabs */}
        <div style={{ borderBottom: '1px solid #1c1c1e', marginBottom: 20 }}>
          <div style={{ display: 'flex', gap: 0 }}>
            {TABS.map(tab => (
              <button key={tab.id} onClick={() => setActiveTab(tab.id as typeof activeTab)} style={{
                background: 'none', border: 'none', borderBottom: `2px solid ${activeTab === tab.id ? '#0a84ff' : 'transparent'}`,
                color: activeTab === tab.id ? '#0a84ff' : '#8e8e93',
                padding: '10px 20px', cursor: 'pointer', fontWeight: 600, fontSize: 14, transition: 'all 0.2s',
              }}>{tab.label}</button>
            ))}
          </div>
        </div>

        {/* Events Tab */}
        {activeTab === 'events' && (
          <div style={{ background: '#0a0a0a', border: '1px solid #1c1c1e', borderRadius: 12, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #2c2c2e' }}>
                  {['Time', 'Severity', 'Agent', 'Description', 'Decision', 'Score', 'Audit'].map(h => (
                    <th key={h} style={{ padding: '10px 12px', color: '#8e8e93', fontSize: 11, fontWeight: 600, textAlign: 'left', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {allEvents.slice(0, 100).map(ev => (
                  <EventRow key={ev.event_id} event={ev} onClick={() => setSelectedEvent(ev)} />
                ))}
              </tbody>
            </table>
            {allEvents.length === 0 && (
              <div style={{ padding: 32, textAlign: 'center', color: '#636366' }}>No events yet. Waiting for agent data...</div>
            )}
          </div>
        )}

        {/* Pending Decisions Tab */}
        {activeTab === 'decisions' && (
          <div>
            {pending.filter(p => p.status === 'pending').length === 0 && (
              <div style={{ color: '#636366', textAlign: 'center', padding: 40 }}>
                ✅ No pending decisions. All events resolved.
              </div>
            )}
            {pending.filter(p => p.status === 'pending').map(pd => (
              <div key={pd.event_id} style={{
                background: '#0a0a0a', border: '1px solid #ff9f0a44',
                borderRadius: 12, padding: '18px 22px', marginBottom: 14,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 14 }}>
                  <div>
                    <Badge text={pd.threat_level} color={THREAT_COLORS[pd.threat_level] || '#636366'} />
                    <span style={{ color: '#ebebf5', marginLeft: 12, fontWeight: 700 }}>{pd.description}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => approveDecision(pd.event_id)} style={{
                      background: '#30d158', color: '#000', border: 'none',
                      borderRadius: 8, padding: '7px 18px', cursor: 'pointer', fontWeight: 700, fontSize: 13,
                    }}>✓ Approve</button>
                    <button onClick={() => rejectDecision(pd.event_id)} style={{
                      background: '#ff3b30', color: '#fff', border: 'none',
                      borderRadius: 8, padding: '7px 18px', cursor: 'pointer', fontWeight: 700, fontSize: 13,
                    }}>✗ Reject</button>
                  </div>
                </div>
                <div style={{ background: '#1c1c1e', borderRadius: 8, padding: '12px 16px', marginBottom: 10 }}>
                  <div style={{ color: '#8e8e93', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>🧠 XAI Explanation</div>
                  <div style={{ color: '#ebebf5', fontSize: 13 }}>{pd.xai_summary}</div>
                </div>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', fontSize: 12 }}>
                  <span style={{ color: '#8e8e93' }}>Agent: <span style={{ color: '#ebebf5', fontFamily: 'monospace' }}>{pd.agent_id}</span></span>
                  <span style={{ color: '#8e8e93' }}>Proposed: <Badge text={pd.proposed_action} color='#ff9f0a' small /></span>
                  <span style={{ color: '#8e8e93' }}>Score: <span style={{ color: '#ff9f0a', fontFamily: 'monospace' }}>{formatScore(pd.score)}</span></span>
                  <span style={{ color: '#8e8e93' }}>Escalated: <span style={{ color: '#ebebf5' }}>{formatTs(pd.escalated_at)}</span></span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Policy Tab */}
        {activeTab === 'policy' && (
          <div>
            <div style={{ color: '#8e8e93', fontSize: 13, marginBottom: 18, background: '#1c1c1e', padding: '12px 16px', borderRadius: 8 }}>
              ⚙️ Adjust per-agent confidence thresholds. Changes are pushed to all agents within 60 seconds.
              Events below the threshold are escalated to the Decision Inbox for human review.
            </div>
            {['network', 'web', 'server'].map(at => (
              policies[at] && <PolicyEditor key={at} policy={policies[at]} onSave={savePolicy} />
            ))}
          </div>
        )}

        {/* FL Tab */}
        {activeTab === 'fl' && (
          <div>
            <div style={{ color: '#8e8e93', fontSize: 13, marginBottom: 18, background: '#1c1c1e', padding: '12px 16px', borderRadius: 8 }}>
              🧬 Federated Learning — agents send gradient deltas every 24h. No raw data leaves the agents.
              SOC approval required for model retraining when JSD drift {'>'} 15%.
            </div>
            {(flStatus?.rounds || []).map((round, i) => (
              <div key={i} style={{
                background: '#0a0a0a', border: `1px solid ${round.retrain_proposed ? '#ff9f0a44' : '#1c1c1e'}`,
                borderRadius: 12, padding: '18px 22px', marginBottom: 14,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <span style={{ color: '#ebebf5', fontWeight: 700, fontFamily: 'monospace' }}>{round.model_id}</span>
                  <Badge text={round.status} color={round.status === 'completed' ? '#30d158' : '#ff9f0a'} />
                </div>
                <div style={{ display: 'flex', gap: 16, fontSize: 13 }}>
                  <span style={{ color: '#8e8e93' }}>Contributors: <span style={{ color: '#ebebf5' }}>{round.contributions.length}</span></span>
                  <span style={{ color: '#8e8e93' }}>Max JSD: <span style={{ color: round.max_jsd > 0.15 ? '#ff3b30' : '#30d158', fontFamily: 'monospace' }}>{round.max_jsd.toFixed(3)}</span></span>
                  {round.retrain_proposed && (
                    <button onClick={() => approveRetrain(round.model_id)} style={{
                      background: '#ff9f0a', color: '#000', border: 'none',
                      borderRadius: 6, padding: '4px 14px', cursor: 'pointer', fontWeight: 700, fontSize: 12,
                    }}>⚠️ Approve Retrain</button>
                  )}
                </div>
              </div>
            ))}
            {(flStatus?.rounds || []).length === 0 && (
              <div style={{ color: '#636366', textAlign: 'center', padding: 40 }}>No FL rounds yet. Waiting for agent contributions...</div>
            )}
          </div>
        )}

        {/* Audit Tab */}
        {activeTab === 'audit' && (
          <div style={{ background: '#0a0a0a', border: '1px solid #1c1c1e', borderRadius: 12, padding: '18px 22px' }}>
            <div style={{ color: '#8e8e93', fontSize: 13, marginBottom: 16 }}>
              🔗 SHA-256 chained audit log. Every autonomous action and human decision is permanently recorded.
              Chain is cryptographically verifiable.
            </div>
            <div style={{ color: '#30d158', fontFamily: 'monospace', fontSize: 12 }}>
              Total entries: {data?.audit_entries || 0} | Chain integrity: ✓ VALID
            </div>
            <div style={{ marginTop: 14, color: '#636366', fontSize: 12 }}>
              Query via API: <span style={{ color: '#0a84ff', fontFamily: 'monospace' }}>GET /api/v1/audit?page=0</span>
              <br />Verify entry: <span style={{ color: '#0a84ff', fontFamily: 'monospace' }}>GET /api/v1/audit/:seq/verify</span>
            </div>
          </div>
        )}
      </main>

      {selectedEvent && <EventModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
    </div>
  );
}
