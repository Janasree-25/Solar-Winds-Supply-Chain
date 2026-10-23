'use client';

import { useEffect, useState, useRef, useCallback } from 'react';

// ─── Type Definitions ────────────────────────────────────────────────────────

interface Stats {
  total_organizations: number;
  total_vulnerabilities: number;
  total_incidents: number;
  avg_cvss: number;
}

interface Organization {
  id: number;
  name: string;
  sector: string;
  country: string;
  affected_date: string;
  breach_status: string;
  systems_compromised: string;
  data_exfiltrated: string;
  description: string;
}

interface ThreatActor {
  id: number;
  name: string;
  alias: string;
  origin_country: string;
  sophistication_level: string;
  first_observed: string;
  description: string;
}

interface Incident {
  id: number;
  incident_name: string;
  attack_phase: string;
  date_occurred: string;
  attack_vector: string;
  severity_level: string;
  description: string;
  impact: string;
  threat_actor_name: string;
  threat_actor_alias: string;
  target_org_name: string;
  target_org_sector: string;
}

interface Vulnerability {
  id: number;
  cve_id: string;
  name: string;
  cvss_score: number;
  vulnerability_type: string;
  affected_software: string;
  date_published: string;
  date_patched: string | null;
  exploit_available: boolean;
  description: string;
}

interface DefenseMeasure {
  id: number;
  measure_name: string;
  category: string;
  implementation_date: string;
  effectiveness_rating: number;
  description: string;
  implementing_org: string;
}

interface TimelineEvent {
  id: number;
  event_date: string;
  event_title: string;
  event_type: string;
  description: string;
  significance_level: string;
}

interface SoftwareVersion {
  id: number;
  product_name: string;
  version: string;
  release_date: string;
  is_compromised: boolean;
  malware_embedded: string | null;
  vulnerability_type: string | null;
  cve_id: string | null;
}

// ─── Helper Components ───────────────────────────────────────────────────────

function AnimatedCounter({ target, suffix = '' }: { target: number; suffix?: string }) {
  const [count, setCount] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const duration = 1200;
    const steps = 60;
    const step = target / steps;
    let current = 0;
    const timer = setInterval(() => {
      current += step;
      if (current >= target) {
        setCount(target);
        clearInterval(timer);
      } else {
        setCount(Math.floor(current));
      }
    }, duration / steps);
    return () => clearInterval(timer);
  }, [target]);

  return (
    <span ref={ref} className="count-up">
      {count}{suffix}
    </span>
  );
}

function SeverityBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    CRITICAL: 'bg-red-100 text-red-800 border-red-200',
    HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
    MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    LOW: 'bg-green-100 text-green-800 border-green-200',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${colors[level] ?? 'bg-gray-100 text-gray-700 border-gray-200'}`}>
      {level}
    </span>
  );
}

function BreachBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    Confirmed: 'bg-red-100 text-red-700 border-red-200',
    Suspected: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    Unaffected: 'bg-green-100 text-green-700 border-green-200',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${colors[status] ?? 'bg-gray-100 text-gray-600 border-gray-200'}`}>
      {status}
    </span>
  );
}

function CvssBar({ score }: { score: number }) {
  const pct = (score / 10) * 100;
  const color = score >= 9 ? 'bg-red-500' : score >= 7 ? 'bg-orange-500' : score >= 4 ? 'bg-yellow-500' : 'bg-green-500';
  const textColor = score >= 9 ? 'text-red-700' : score >= 7 ? 'text-orange-700' : score >= 4 ? 'text-yellow-700' : 'text-green-700';
  return (
    <div className="flex items-center gap-2">
      <span className={`font-bold text-sm w-8 ${textColor}`}>{score}</span>
      <div className="flex-1 bg-gray-100 rounded-full h-2 overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-700 ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function StarRating({ rating }: { rating: number }) {
  return (
    <div className="flex gap-0.5">
      {[1, 2, 3, 4, 5].map((i) => (
        <span key={i} className={i <= rating ? 'text-amber-400' : 'text-gray-200'}>★</span>
      ))}
    </div>
  );
}

function TimelineDot({ type }: { type: string }) {
  const colors: Record<string, string> = {
    attack: 'bg-red-500 ring-red-200',
    discovery: 'bg-orange-500 ring-orange-200',
    response: 'bg-blue-500 ring-blue-200',
    attribution: 'bg-purple-500 ring-purple-200',
  };
  return (
    <div className={`w-4 h-4 rounded-full ring-4 flex-shrink-0 ${colors[type] ?? 'bg-gray-400 ring-gray-200'}`} />
  );
}

function EventTypeBadge({ type }: { type: string }) {
  const styles: Record<string, string> = {
    attack: 'bg-red-100 text-red-700',
    discovery: 'bg-orange-100 text-orange-700',
    response: 'bg-blue-100 text-blue-700',
    attribution: 'bg-purple-100 text-purple-700',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${styles[type] ?? 'bg-gray-100 text-gray-600'}`}>
      {type}
    </span>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-3">
      {[1, 2, 3].map((i) => (
        <div key={i} className="shimmer h-12 rounded-lg" />
      ))}
    </div>
  );
}

// ─── Shield SVG Icon ─────────────────────────────────────────────────────────

function ShieldIcon({ className = 'w-8 h-8' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z"
        fill="url(#shieldGrad)"
        stroke="#0D9488"
        strokeWidth="1.5"
      />
      <path d="M9 12l2 2 4-4" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <defs>
        <linearGradient id="shieldGrad" x1="4" y1="2" x2="20" y2="23" gradientUnits="userSpaceOnUse">
          <stop stopColor="#0D9488" />
          <stop offset="1" stopColor="#1E3A5F" />
        </linearGradient>
      </defs>
    </svg>
  );
}

// ─── Tab Button ──────────────────────────────────────────────────────────────

type Tab = 'overview' | 'timeline' | 'organizations' | 'vulnerabilities' | 'defense' | 'sql';

// ─── Preset Queries ───────────────────────────────────────────────────────────

const PRESET_QUERIES = [
  {
    label: '📋 All Tables',
    sql: 'SHOW TABLES;',
  },
  {
    label: '🎯 All Threat Actors',
    sql: 'SELECT * FROM threat_actors;',
  },
  {
    label: '🏢 All Organizations',
    sql: 'SELECT name, sector, country, breach_status, affected_date FROM organizations ORDER BY breach_status;',
  },
  {
    label: '💿 Compromised Versions',
    sql: "SELECT product_name, version, malware_embedded, cve_id FROM software_versions WHERE is_compromised = TRUE ORDER BY release_date;",
  },
  {
    label: '🛡️ Critical Vulnerabilities',
    sql: 'SELECT cve_id, name, cvss_score, vulnerability_type FROM vulnerabilities WHERE cvss_score >= 9.0 ORDER BY cvss_score DESC;',
  },
  {
    label: '⚡ Incidents by Severity',
    sql: "SELECT incident_name, attack_phase, date_occurred, severity_level FROM attack_incidents ORDER BY FIELD(severity_level,'CRITICAL','HIGH','MEDIUM','LOW');",
  },
  {
    label: '📅 Full Attack Timeline',
    sql: "SELECT event_date, event_title, event_type, significance_level FROM timeline_events ORDER BY event_date;",
  },
  {
    label: '🔒 Defense Measures',
    sql: 'SELECT measure_name, category, effectiveness_rating, implementing_org FROM defense_measures ORDER BY effectiveness_rating DESC;',
  },
  {
    label: '🔗 Incidents with Actor & Target',
    sql: 'SELECT ai.incident_name, ta.name AS threat_actor, o.name AS target_org, ai.severity_level, ai.date_occurred FROM attack_incidents ai JOIN threat_actors ta ON ai.threat_actor_id = ta.id JOIN organizations o ON ai.target_org_id = o.id ORDER BY ai.date_occurred;',
  },
  {
    label: '📊 Org Breach Summary',
    sql: "SELECT breach_status, COUNT(*) AS total, GROUP_CONCAT(name SEPARATOR ', ') AS organizations FROM organizations GROUP BY breach_status;",
  },
];

// ─── SQL Query Runner Component ───────────────────────────────────────────────

interface QueryResult {
  columns: string[];
  rows: Record<string, unknown>[];
  rowCount: number;
  executionMs: number;
  error?: string;
}

function SqlQueryRunner() {
  const [sql, setSql] = useState('SELECT * FROM threat_actors;');
  const [result, setResult] = useState<QueryResult | null>(null);
  const [running, setRunning] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const runQuery = useCallback(async (queryToRun?: string) => {
    const toRun = queryToRun ?? sql;
    if (!toRun.trim()) return;
    setRunning(true);
    setResult(null);
    try {
      const res = await fetch('/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sql: toRun }),
      });
      const data = await res.json();
      setResult(data);
    } catch {
      setResult({ columns: [], rows: [], rowCount: 0, executionMs: 0, error: 'Network error. Is the server running?' });
    } finally {
      setRunning(false);
    }
  }, [sql]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runQuery();
    }
  };

  const loadPreset = (presetSql: string) => {
    setSql(presetSql);
    setResult(null);
    textareaRef.current?.focus();
  };

  return (
    <section className="space-y-6">
      {/* Header */}
      <div className="glass-card rounded-2xl p-6 border-l-4 border-teal-500">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-xl bg-teal-100 flex items-center justify-center text-xl">🖥️</div>
          <div>
            <h2 className="text-xl font-bold text-slate-800">SQL Query Console</h2>
            <p className="text-sm text-slate-500">Run live SQL queries against the <span className="font-semibold text-teal-600">solarwinds_defense</span> database</p>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-400">
          <span className="px-2 py-1 bg-teal-50 text-teal-700 rounded-full border border-teal-200">✅ SELECT</span>
          <span className="px-2 py-1 bg-teal-50 text-teal-700 rounded-full border border-teal-200">✅ SHOW</span>
          <span className="px-2 py-1 bg-teal-50 text-teal-700 rounded-full border border-teal-200">✅ DESCRIBE</span>
          <span className="px-2 py-1 bg-teal-50 text-teal-700 rounded-full border border-teal-200">✅ EXPLAIN</span>
          <span className="px-2 py-1 bg-red-50 text-red-600 rounded-full border border-red-200">❌ INSERT / UPDATE / DELETE</span>
        </div>
      </div>

      {/* Preset Queries */}
      <div className="glass-card rounded-2xl p-5">
        <h3 className="text-sm font-bold text-slate-600 mb-3 uppercase tracking-wide">⚡ Quick Preset Queries</h3>
        <div className="flex flex-wrap gap-2">
          {PRESET_QUERIES.map((pq) => (
            <button
              key={pq.label}
              onClick={() => loadPreset(pq.sql)}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-sky-50 text-sky-700 border border-sky-200 hover:bg-teal-50 hover:text-teal-700 hover:border-teal-300 transition-all duration-150 whitespace-nowrap"
            >
              {pq.label}
            </button>
          ))}
        </div>
      </div>

      {/* Query Editor */}
      <div className="glass-card rounded-2xl overflow-hidden border border-sky-200">
        {/* Editor Top Bar */}
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-sky-100" style={{ background: 'linear-gradient(90deg, #1E3A5F, #0D9488)' }}>
          <div className="flex items-center gap-2">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-400" />
              <div className="w-3 h-3 rounded-full bg-yellow-400" />
              <div className="w-3 h-3 rounded-full bg-green-400" />
            </div>
            <span className="text-xs text-sky-200 font-mono ml-2">solarwinds_defense &gt; query.sql</span>
          </div>
          <span className="text-xs text-sky-300">Ctrl + Enter to run</span>
        </div>

        {/* Textarea */}
        <div className="relative">
          <textarea
            ref={textareaRef}
            value={sql}
            onChange={(e) => setSql(e.target.value)}
            onKeyDown={handleKeyDown}
            rows={6}
            spellCheck={false}
            className="w-full p-4 font-mono text-sm text-slate-700 bg-white resize-y focus:outline-none leading-relaxed border-0"
            placeholder="Type your SQL query here... e.g. SELECT * FROM organizations;"
            style={{ minHeight: '140px' }}
          />
        </div>

        {/* Bottom Action Bar */}
        <div className="flex items-center justify-between px-4 py-3 bg-slate-50 border-t border-sky-100">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSql('')}
              className="px-3 py-1.5 text-xs text-slate-500 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors border border-slate-200"
            >
              🗑️ Clear
            </button>
            <button
              onClick={() => { setSql('SELECT * FROM threat_actors;'); setResult(null); }}
              className="px-3 py-1.5 text-xs text-slate-500 hover:text-slate-700 hover:bg-slate-100 rounded-lg transition-colors border border-slate-200"
            >
              ↺ Reset
            </button>
          </div>
          <button
            onClick={() => runQuery()}
            disabled={running || !sql.trim()}
            className={`flex items-center gap-2 px-5 py-2 rounded-lg font-semibold text-sm transition-all duration-200 shadow-sm ${
              running || !sql.trim()
                ? 'bg-slate-200 text-slate-400 cursor-not-allowed'
                : 'bg-gradient-to-r from-teal-600 to-emerald-600 text-white hover:from-teal-700 hover:to-emerald-700 shadow-teal-200 hover:shadow-md active:scale-95'
            }`}
          >
            {running ? (
              <>
                <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Running...
              </>
            ) : (
              <>▶ Run Query</>
            )}
          </button>
        </div>
      </div>

      {/* Results Panel */}
      {result && (
        <div className="glass-card rounded-2xl overflow-hidden border border-sky-200 fade-in-up">
          {/* Results Header */}
          <div className="flex items-center justify-between px-5 py-3 border-b border-sky-100 bg-white">
            <div className="flex items-center gap-3">
              <span className="text-base font-bold text-slate-700">Query Results</span>
              {!result.error && (
                <>
                  <span className="px-2.5 py-0.5 bg-emerald-100 text-emerald-700 rounded-full text-xs font-bold border border-emerald-200">
                    ✓ {result.rowCount} row{result.rowCount !== 1 ? 's' : ''}
                  </span>
                  <span className="px-2.5 py-0.5 bg-sky-100 text-sky-700 rounded-full text-xs font-medium border border-sky-200">
                    ⏱ {result.executionMs}ms
                  </span>
                </>
              )}
            </div>
            {!result.error && result.columns.length > 0 && (
              <span className="text-xs text-slate-400">{result.columns.length} column{result.columns.length !== 1 ? 's' : ''}</span>
            )}
          </div>

          {/* Error */}
          {result.error ? (
            <div className="p-5">
              <div className="flex items-start gap-3 p-4 bg-red-50 border border-red-200 rounded-xl">
                <span className="text-xl flex-shrink-0">❌</span>
                <div>
                  <div className="font-semibold text-red-700 text-sm mb-1">Query Error</div>
                  <code className="text-red-600 text-xs font-mono leading-relaxed">{result.error}</code>
                </div>
              </div>
            </div>
          ) : result.rowCount === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-400">
              <span className="text-4xl mb-3">📭</span>
              <p className="font-medium text-slate-500">No rows returned</p>
              <p className="text-sm mt-1">The query executed successfully but returned 0 results.</p>
            </div>
          ) : (
            <div className="overflow-auto max-h-[520px]">
              <table className="w-full text-sm border-collapse">
                <thead className="sticky top-0 z-10">
                  <tr style={{ background: 'linear-gradient(90deg, #0D9488, #059669)' }}>
                    <th className="text-left py-2.5 px-4 text-white font-semibold text-xs uppercase tracking-wide w-10 border-r border-teal-500/30">#</th>
                    {result.columns.map((col) => (
                      <th
                        key={col}
                        className="text-left py-2.5 px-4 text-white font-semibold text-xs uppercase tracking-wide whitespace-nowrap border-r border-teal-500/30 last:border-r-0"
                      >
                        {col}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.rows.map((row, ri) => (
                    <tr
                      key={ri}
                      className={`border-b border-sky-50 hover:bg-teal-50/60 transition-colors ${ri % 2 === 0 ? 'bg-white' : 'bg-sky-50/30'}`}
                    >
                      <td className="py-2.5 px-4 text-slate-400 font-mono text-xs border-r border-sky-100 w-10">{ri + 1}</td>
                      {result.columns.map((col) => {
                        const val = row[col];
                        const display = val === null || val === undefined ? 'NULL' : String(val);
                        const isNull = val === null || val === undefined;
                        const isBool = typeof val === 'boolean' || display === '0' || display === '1';
                        return (
                          <td
                            key={col}
                            className="py-2.5 px-4 border-r border-sky-50 last:border-r-0 max-w-[280px]"
                            title={display}
                          >
                            {isNull ? (
                              <span className="text-slate-300 font-mono text-xs italic">NULL</span>
                            ) : (
                              <span className={`text-xs leading-relaxed block truncate ${
                                isBool
                                  ? display === '1' || display === 'true'
                                    ? 'text-emerald-600 font-semibold'
                                    : 'text-red-500 font-semibold'
                                  : 'text-slate-700'
                              }`}>
                                {display}
                              </span>
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function TabButton({ id, label, icon, active, onClick }: {
  id: Tab; label: string; icon: string; active: boolean; onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium text-sm transition-all duration-200 ${
        active
          ? 'bg-teal-600 text-white shadow-md shadow-teal-200'
          : 'text-slate-600 hover:bg-sky-100 hover:text-teal-700'
      }`}
    >
      <span>{icon}</span>
      {label}
    </button>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [stats, setStats] = useState<Stats | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [threatActors, setThreatActors] = useState<ThreatActor[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [defense, setDefense] = useState<DefenseMeasure[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [software, setSoftware] = useState<SoftwareVersion[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchAll() {
      try {
        const [s, o, ta, inc, v, d, t, sw] = await Promise.all([
          fetch('/api/stats').then((r) => r.json()),
          fetch('/api/organizations').then((r) => r.json()),
          fetch('/api/threat-actors').then((r) => r.json()),
          fetch('/api/incidents').then((r) => r.json()),
          fetch('/api/vulnerabilities').then((r) => r.json()),
          fetch('/api/defense').then((r) => r.json()),
          fetch('/api/timeline').then((r) => r.json()),
          fetch('/api/software').then((r) => r.json()),
        ]);
        setStats(s && !s.error ? s : null);
        setOrganizations(Array.isArray(o) ? o : []);
        setThreatActors(Array.isArray(ta) ? ta : []);
        setIncidents(Array.isArray(inc) ? inc : []);
        setVulnerabilities(Array.isArray(v) ? v : []);
        setDefense(Array.isArray(d) ? d : []);
        setTimeline(Array.isArray(t) ? t : []);
        setSoftware(Array.isArray(sw) ? sw : []);
      } catch (err) {
        console.error('Fetch error:', err);
      } finally {
        setLoading(false);
      }
    }
    fetchAll();
  }, []);

  const formatDate = (d: string) => {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  };

  const tabs: { id: Tab; label: string; icon: string }[] = [
    { id: 'overview', label: 'Overview', icon: '🔍' },
    { id: 'timeline', label: 'Timeline', icon: '📅' },
    { id: 'organizations', label: 'Organizations', icon: '🏢' },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '🛡️' },
    { id: 'defense', label: 'Defense Measures', icon: '🔒' },
    { id: 'sql', label: 'SQL Console', icon: '🖥️' },
  ];

  return (
    <div className="min-h-screen" style={{ background: '#F0F9FF' }}>
      {/* ── Header ── */}
      <header
        className="relative overflow-hidden"
        style={{ background: 'linear-gradient(135deg, #1E3A5F 0%, #0D9488 60%, #059669 100%)' }}
      >
        <div className="absolute inset-0 opacity-10">
          <div className="absolute -top-16 -right-16 w-64 h-64 rounded-full border border-white/20" />
          <div className="absolute top-8 right-32 w-32 h-32 rounded-full border border-white/10" />
          <div className="absolute -bottom-8 left-32 w-48 h-48 rounded-full border border-white/10" />
        </div>
        <div className="relative max-w-7xl mx-auto px-6 py-8">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-2xl" style={{ background: 'rgba(255,255,255,0.15)', backdropFilter: 'blur(8px)' }}>
              <ShieldIcon className="w-10 h-10" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white tracking-tight">
                SolarWinds Supply Chain Defense
              </h1>
              <p className="text-sky-200 mt-1 text-base font-medium">
                Cybersecurity Case Study Dashboard · SUNBURST Attack Analysis
              </p>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-3">
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-white/10 text-sky-100 border border-white/20">
              🎯 APT29 / Cozy Bear
            </span>
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-white/10 text-sky-100 border border-white/20">
              📅 2019–2022
            </span>
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-white/10 text-sky-100 border border-white/20">
              🌐 Nation-State Supply Chain Attack
            </span>
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-red-400/30 text-red-100 border border-red-300/30">
              ⚠️ 18,000+ Organizations Affected
            </span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* ── Stats Cards ── */}
        {loading ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[1,2,3,4].map(i => <div key={i} className="shimmer h-32 rounded-2xl" />)}
          </div>
        ) : stats ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 fade-in-up">
            {[
              { label: 'Organizations Affected', value: stats.total_organizations, icon: '🏢', color: 'border-teal-400', bg: 'bg-teal-50', iconBg: 'bg-teal-100' },
              { label: 'Vulnerabilities Tracked', value: stats.total_vulnerabilities, icon: '🛡️', color: 'border-red-400', bg: 'bg-red-50', iconBg: 'bg-red-100' },
              { label: 'Attack Incidents', value: stats.total_incidents, icon: '⚡', color: 'border-orange-400', bg: 'bg-orange-50', iconBg: 'bg-orange-100' },
              { label: 'Avg CVSS Score', value: stats.avg_cvss, icon: '📊', color: 'border-purple-400', bg: 'bg-purple-50', iconBg: 'bg-purple-100', suffix: '/10' },
            ].map((card) => (
              <div
                key={card.label}
                className={`glass-card rounded-2xl p-5 border-l-4 ${card.color} ${card.bg}`}
              >
                <div className={`w-10 h-10 rounded-xl ${card.iconBg} flex items-center justify-center text-xl mb-3`}>
                  {card.icon}
                </div>
                <div className="text-3xl font-extrabold text-slate-800">
                  <AnimatedCounter target={Number(card.value)} suffix={card.suffix ?? ''} />
                </div>
                <div className="text-sm text-slate-500 mt-1 font-medium">{card.label}</div>
              </div>
            ))}
          </div>
        ) : null}

        {/* ── Attack Incidents (always visible) ── */}
        <section className="glass-card rounded-2xl p-6">
          <h2 className="text-lg font-bold text-slate-800 mb-4 flex items-center gap-2">
            <span className="text-2xl">⚡</span> Attack Incidents
          </h2>
          {loading ? <LoadingSkeleton /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-sky-100">
                    <th className="text-left py-2 px-3 font-semibold text-teal-700">Incident</th>
                    <th className="text-left py-2 px-3 font-semibold text-teal-700">Phase</th>
                    <th className="text-left py-2 px-3 font-semibold text-teal-700">Date</th>
                    <th className="text-left py-2 px-3 font-semibold text-teal-700">Target</th>
                    <th className="text-left py-2 px-3 font-semibold text-teal-700">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc) => (
                    <tr key={inc.id} className="border-b border-sky-50 hover:bg-sky-50 transition-colors group">
                      <td className="py-2.5 px-3 font-medium text-slate-700 max-w-[200px]">
                        <div className="truncate" title={inc.incident_name}>{inc.incident_name}</div>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 bg-sky-100 text-sky-700 rounded text-xs font-medium">{inc.attack_phase}</span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap">{formatDate(inc.date_occurred)}</td>
                      <td className="py-2.5 px-3 text-slate-600 max-w-[160px]">
                        <div className="truncate" title={inc.target_org_name}>{inc.target_org_name}</div>
                      </td>
                      <td className="py-2.5 px-3"><SeverityBadge level={inc.severity_level} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* ── Navigation Tabs ── */}
        <div className="flex flex-wrap gap-2 bg-white/70 rounded-xl p-2 border border-sky-100 shadow-sm">
          {tabs.map((t) => (
            <TabButton
              key={t.id}
              {...t}
              active={activeTab === t.id}
              onClick={() => setActiveTab(t.id)}
            />
          ))}
          {/* SQL Console — special highlighted tab */}
          <button
            onClick={() => setActiveTab('sql')}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-bold text-sm transition-all duration-200 ml-auto ${
              activeTab === 'sql'
                ? 'bg-gradient-to-r from-teal-600 to-emerald-600 text-white shadow-md shadow-teal-200 scale-105'
                : 'bg-gradient-to-r from-teal-50 to-emerald-50 text-teal-700 border border-teal-200 hover:from-teal-100 hover:to-emerald-100'
            }`}
          >
            <span>🖥️</span> SQL Console
          </button>
        </div>

        {/* ── Tab Content ── */}
        <div className="fade-in-up">

          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Threat Actors */}
              <section className="glass-card rounded-2xl p-6">
                <h2 className="text-lg font-bold text-slate-800 mb-4 flex items-center gap-2">
                  <span className="text-2xl">🎯</span> Threat Actors
                </h2>
                {loading ? <LoadingSkeleton /> : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr style={{ background: 'linear-gradient(90deg, #0D9488, #059669)' }}>
                          {['Name', 'Alias / Designation', 'Origin', 'Sophistication', 'First Observed'].map((h) => (
                            <th key={h} className="text-left py-2.5 px-3 text-white font-semibold text-xs uppercase tracking-wide first:rounded-tl-lg last:rounded-tr-lg">
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {threatActors.map((ta, idx) => (
                          <tr key={ta.id} className={`border-b border-sky-50 hover:bg-sky-50 transition-colors ${idx % 2 === 0 ? 'bg-white' : 'bg-sky-50/30'}`}>
                            <td className="py-2.5 px-3 font-bold text-teal-700">{ta.name}</td>
                            <td className="py-2.5 px-3 text-slate-600 max-w-[200px]">
                              <div className="truncate text-xs" title={ta.alias}>{ta.alias ?? '—'}</div>
                            </td>
                            <td className="py-2.5 px-3">
                              <span className="flex items-center gap-1">
                                🇷🇺 <span className="text-slate-600">{ta.origin_country}</span>
                              </span>
                            </td>
                            <td className="py-2.5 px-3">
                              <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded-full text-xs font-semibold">
                                {ta.sophistication_level}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap">{formatDate(ta.first_observed)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              {/* Software Versions */}
              <section className="glass-card rounded-2xl p-6">
                <h2 className="text-lg font-bold text-slate-800 mb-4 flex items-center gap-2">
                  <span className="text-2xl">💿</span> Affected Software Versions
                </h2>
                {loading ? <LoadingSkeleton /> : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr style={{ background: 'linear-gradient(90deg, #1E3A5F, #1E40AF)' }}>
                          {['Product', 'Version', 'Release Date', 'Status', 'Malware', 'CVE'].map((h) => (
                            <th key={h} className="text-left py-2.5 px-3 text-white font-semibold text-xs uppercase tracking-wide first:rounded-tl-lg last:rounded-tr-lg">
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {software.map((sw, idx) => (
                          <tr
                            key={sw.id}
                            className={`border-b border-sky-50 hover:bg-sky-50 transition-colors ${
                              sw.is_compromised ? 'bg-red-50/60' : idx % 2 === 0 ? 'bg-white' : 'bg-sky-50/20'
                            }`}
                          >
                            <td className="py-2.5 px-3 font-medium text-slate-700 text-xs">{sw.product_name}</td>
                            <td className="py-2.5 px-3">
                              <span className={`font-mono text-xs font-bold ${sw.is_compromised ? 'text-red-700' : 'text-green-700'}`}>
                                {sw.version}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-slate-500 text-xs whitespace-nowrap">{formatDate(sw.release_date)}</td>
                            <td className="py-2.5 px-3">
                              {sw.is_compromised ? (
                                <span className="flex items-center gap-1 text-red-600 font-semibold text-xs">
                                  <span className="w-2 h-2 rounded-full bg-red-500 inline-block" /> COMPROMISED
                                </span>
                              ) : (
                                <span className="flex items-center gap-1 text-green-600 font-semibold text-xs">
                                  <span className="w-2 h-2 rounded-full bg-green-500 inline-block" /> CLEAN
                                </span>
                              )}
                            </td>
                            <td className="py-2.5 px-3 text-xs text-slate-500 max-w-[160px]">
                              <div className="truncate" title={sw.malware_embedded ?? ''}>{sw.malware_embedded ?? '—'}</div>
                            </td>
                            <td className="py-2.5 px-3">
                              {sw.cve_id ? (
                                <span className="px-1.5 py-0.5 bg-orange-100 text-orange-700 rounded text-xs font-mono">{sw.cve_id}</span>
                              ) : '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </div>
          )}

          {/* TIMELINE TAB */}
          {activeTab === 'timeline' && (
            <section className="glass-card rounded-2xl p-6">
              <h2 className="text-lg font-bold text-slate-800 mb-2 flex items-center gap-2">
                <span className="text-2xl">📅</span> Attack Timeline
              </h2>
              <div className="flex flex-wrap gap-3 mb-6">
                {[
                  { type: 'attack', label: 'Attack', color: 'bg-red-500' },
                  { type: 'discovery', label: 'Discovery', color: 'bg-orange-500' },
                  { type: 'response', label: 'Response', color: 'bg-blue-500' },
                  { type: 'attribution', label: 'Attribution', color: 'bg-purple-500' },
                ].map((l) => (
                  <span key={l.type} className="flex items-center gap-1.5 text-xs text-slate-600">
                    <span className={`w-3 h-3 rounded-full ${l.color}`} />{l.label}
                  </span>
                ))}
              </div>
              {loading ? <LoadingSkeleton /> : (
                <div className="relative">
                  <div className="absolute left-[7px] top-0 bottom-0 w-0.5 bg-gradient-to-b from-sky-200 via-sky-300 to-sky-100" />
                  <div className="space-y-6 pl-8">
                    {timeline.map((ev) => (
                      <div key={ev.id} className="relative group">
                        <div className="absolute -left-8 top-1 flex items-center">
                          <TimelineDot type={ev.event_type} />
                        </div>
                        <div className="bg-white rounded-xl p-4 border border-sky-100 shadow-sm hover:shadow-md hover:border-sky-200 transition-all duration-200">
                          <div className="flex flex-wrap items-center gap-2 mb-1">
                            <span className="text-xs text-slate-400 font-medium whitespace-nowrap">{formatDate(ev.event_date)}</span>
                            <EventTypeBadge type={ev.event_type} />
                            {ev.significance_level === 'CRITICAL' && (
                              <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded text-xs font-bold">🔥 Critical</span>
                            )}
                          </div>
                          <h3 className="font-bold text-slate-800 text-sm">{ev.event_title}</h3>
                          <p className="text-slate-500 text-xs mt-1 leading-relaxed">{ev.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}

          {/* ORGANIZATIONS TAB */}
          {activeTab === 'organizations' && (
            <section>
              <h2 className="text-lg font-bold text-slate-800 mb-4 flex items-center gap-2">
                <span className="text-2xl">🏢</span> Affected Organizations
              </h2>
              {loading ? <LoadingSkeleton /> : (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                  {organizations.map((org) => (
                    <div
                      key={org.id}
                      className="glass-card rounded-2xl p-5 hover:shadow-lg hover:border-teal-200 transition-all duration-200 group border border-sky-100"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <h3 className="font-bold text-slate-800 text-sm leading-tight group-hover:text-teal-700 transition-colors">
                          {org.name}
                        </h3>
                        <BreachBadge status={org.breach_status} />
                      </div>
                      <div className="space-y-1.5 text-xs text-slate-500">
                        <div className="flex items-center gap-1.5">
                          <span>🏷️</span>
                          <span className="font-medium text-slate-600">{org.sector}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span>🌍</span>
                          <span>{org.country}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span>📅</span>
                          <span>Affected: {formatDate(org.affected_date)}</span>
                        </div>
                        {org.systems_compromised && (
                          <div className="mt-2 pt-2 border-t border-sky-100">
                            <span className="font-semibold text-slate-600 block mb-0.5">Systems Compromised:</span>
                            <span className="leading-relaxed line-clamp-2">{org.systems_compromised}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}

          {/* VULNERABILITIES TAB */}
          {activeTab === 'vulnerabilities' && (
            <section className="glass-card rounded-2xl p-6">
              <h2 className="text-lg font-bold text-slate-800 mb-4 flex items-center gap-2">
                <span className="text-2xl">🛡️</span> Vulnerabilities
              </h2>
              {loading ? <LoadingSkeleton /> : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b-2 border-sky-100">
                        {['CVE ID', 'Name', 'CVSS Score', 'Type', 'Published', 'Patched', 'Exploit'].map((h) => (
                          <th key={h} className="text-left py-3 px-3 font-semibold text-teal-700 text-xs uppercase tracking-wide">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {vulnerabilities.map((v, idx) => (
                        <tr key={v.id} className={`border-b border-sky-50 hover:bg-sky-50 transition-colors ${idx % 2 === 0 ? 'bg-white' : 'bg-sky-50/20'}`}>
                          <td className="py-3 px-3">
                            <span className="font-mono text-xs font-bold text-blue-700 bg-blue-50 px-2 py-0.5 rounded whitespace-nowrap">
                              {v.cve_id}
                            </span>
                          </td>
                          <td className="py-3 px-3 font-medium text-slate-700 max-w-[200px]">
                            <div className="text-xs leading-tight" title={v.name}>{v.name}</div>
                          </td>
                          <td className="py-3 px-3 min-w-[130px]">
                            <CvssBar score={Number(v.cvss_score)} />
                          </td>
                          <td className="py-3 px-3">
                            <span className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded text-xs">{v.vulnerability_type}</span>
                          </td>
                          <td className="py-3 px-3 text-slate-500 text-xs whitespace-nowrap">{formatDate(v.date_published)}</td>
                          <td className="py-3 px-3 text-slate-500 text-xs whitespace-nowrap">
                            {v.date_patched ? formatDate(v.date_patched) : <span className="text-red-500">Unpatched</span>}
                          </td>
                          <td className="py-3 px-3">
                            {v.exploit_available ? (
                              <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded-full text-xs font-semibold">⚠️ Yes</span>
                            ) : (
                              <span className="px-2 py-0.5 bg-green-100 text-green-700 rounded-full text-xs font-semibold">✓ No</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}

          {/* DEFENSE MEASURES TAB */}
          {activeTab === 'defense' && (
            <section>
              <h2 className="text-lg font-bold text-slate-800 mb-4 flex items-center gap-2">
                <span className="text-2xl">🔒</span> Defense Measures
              </h2>
              {loading ? <LoadingSkeleton /> : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {defense.map((d) => (
                    <div
                      key={d.id}
                      className="glass-card rounded-2xl p-5 hover:shadow-lg hover:border-teal-200 transition-all duration-200 border border-sky-100"
                    >
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="font-bold text-slate-800 text-sm leading-tight max-w-[75%]">{d.measure_name}</h3>
                        <span className="px-2 py-0.5 bg-teal-100 text-teal-700 rounded text-xs font-medium ml-2 whitespace-nowrap">{d.category}</span>
                      </div>
                      <div className="flex items-center gap-3 mb-3">
                        <StarRating rating={d.effectiveness_rating} />
                        <span className="text-xs text-slate-400">{d.effectiveness_rating}/5 effectiveness</span>
                      </div>
                      <div className="w-full bg-gray-100 rounded-full h-1.5 mb-3">
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-teal-400 to-emerald-500 transition-all duration-700"
                          style={{ width: `${(d.effectiveness_rating / 5) * 100}%` }}
                        />
                      </div>
                      <p className="text-xs text-slate-500 leading-relaxed line-clamp-3">{d.description}</p>
                      <div className="mt-3 pt-2 border-t border-sky-50 flex items-center gap-1.5 text-xs text-slate-400">
                        <span>🏛️</span>
                        <span className="font-medium text-slate-500">{d.implementing_org}</span>
                        <span className="ml-auto">{formatDate(d.implementation_date)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}

          {/* SQL CONSOLE TAB */}
          {activeTab === 'sql' && <SqlQueryRunner />}
        </div>
      </main>

      {/* ── Footer ── */}
      <footer className="mt-12 border-t border-sky-200 bg-white/50">
        <div className="max-w-7xl mx-auto px-6 py-6 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <ShieldIcon className="w-4 h-4" />
            <span className="font-semibold text-slate-600">SolarWinds Supply Chain Defense</span>
          </div>
          <span>Cybersecurity Case Study · SUNBURST / APT29 · For Educational Purposes</span>
        </div>
      </footer>
    </div>
  );
}
