import { query } from '@/lib/db';
import {
  SEED_THREAT_ACTORS,
  SEED_ORGANIZATIONS,
  SEED_SOFTWARE,
  SEED_INCIDENTS,
  SEED_VULNERABILITIES,
  SEED_DEFENSE,
  SEED_TIMELINE,
} from '@/lib/seed-data';

interface TableMap {
  [key: string]: Record<string, unknown>[];
}

const TABLES: TableMap = {
  threat_actors: SEED_THREAT_ACTORS,
  organizations: SEED_ORGANIZATIONS,
  software_versions: SEED_SOFTWARE,
  attack_incidents: SEED_INCIDENTS,
  vulnerabilities: SEED_VULNERABILITIES,
  defense_measures: SEED_DEFENSE,
  timeline_events: SEED_TIMELINE,
};

function executeInMemoryQuery(sql: string): { columns: string[]; rows: Record<string, unknown>[] } {
  const clean = sql.trim().replace(/;+$/, '').trim();
  const lower = clean.toLowerCase();

  // 1. SHOW TABLES
  if (/^show\s+tables/i.test(clean)) {
    const tableNames = Object.keys(TABLES).map((t) => ({ Tables_in_solarwinds_defense: t }));
    return {
      columns: ['Tables_in_solarwinds_defense'],
      rows: tableNames,
    };
  }

  // 2. SHOW DATABASES
  if (/^show\s+databases/i.test(clean)) {
    return {
      columns: ['Database'],
      rows: [{ Database: 'solarwinds_defense' }, { Database: 'information_schema' }],
    };
  }

  // 3. DESCRIBE / DESC <table>
  const descMatch = clean.match(/^(?:describe|desc)\s+([a-zA-Z0-9_]+)/i);
  if (descMatch) {
    const tableKey = descMatch[1].toLowerCase();
    const data = TABLES[tableKey];
    if (data && data.length > 0) {
      const sample = data[0];
      const rows = Object.keys(sample).map((key) => ({
        Field: key,
        Type: typeof sample[key] === 'number' ? 'int/decimal' : typeof sample[key] === 'boolean' ? 'boolean' : 'varchar/text',
        Null: 'YES',
        Key: key === 'id' ? 'PRI' : '',
        Default: null,
        Extra: key === 'id' ? 'auto_increment' : '',
      }));
      return { columns: ['Field', 'Type', 'Null', 'Key', 'Default', 'Extra'], rows };
    }
  }

  // 4. Incident JOIN Query: SELECT ai.incident_name, ta.name AS threat_actor, o.name AS target_org ...
  if (lower.includes('join threat_actors') || (lower.includes('attack_incidents') && lower.includes('threat_actors'))) {
    const rows = SEED_INCIDENTS.map((inc) => ({
      incident_name: inc.incident_name,
      threat_actor: inc.threat_actor_name,
      target_org: inc.target_org_name,
      severity_level: inc.severity_level,
      date_occurred: inc.date_occurred,
    }));
    return {
      columns: ['incident_name', 'threat_actor', 'target_org', 'severity_level', 'date_occurred'],
      rows,
    };
  }

  // 5. Org Breach Summary GROUP BY: SELECT breach_status, COUNT(*) AS total ...
  if (lower.includes('organizations') && lower.includes('group by') && lower.includes('breach_status')) {
    const groups: Record<string, { total: number; names: string[] }> = {};
    SEED_ORGANIZATIONS.forEach((o) => {
      const st = o.breach_status;
      if (!groups[st]) groups[st] = { total: 0, names: [] };
      groups[st].total += 1;
      groups[st].names.push(o.name);
    });
    const rows = Object.keys(groups).map((status) => ({
      breach_status: status,
      total: groups[status].total,
      organizations: groups[status].names.join(', '),
    }));
    return {
      columns: ['breach_status', 'total', 'organizations'],
      rows,
    };
  }

  // 6. Generic SELECT from known tables
  for (const [tableName, dataset] of Object.entries(TABLES)) {
    if (lower.includes(tableName)) {
      let filtered = [...dataset];

      // CVSS >= 9.0 filter
      if (lower.includes('cvss_score >= 9') || lower.includes('cvss_score >= 9.0')) {
        filtered = filtered.filter((r) => Number(r.cvss_score) >= 9.0);
      } else if (lower.includes('cvss_score >=')) {
        const m = lower.match(/cvss_score\s*>=\s*([0-9.]+)/);
        if (m) {
          const val = parseFloat(m[1]);
          filtered = filtered.filter((r) => Number(r.cvss_score) >= val);
        }
      }

      // is_compromised = true filter
      if (lower.includes('is_compromised = true') || lower.includes('is_compromised=true') || lower.includes('is_compromised = 1')) {
        filtered = filtered.filter((r) => r.is_compromised === true);
      }

      // Severity order
      if (lower.includes('field(severity_level')) {
        const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        filtered.sort((a, b) => {
          const aIdx = order.indexOf(String(a.severity_level));
          const bIdx = order.indexOf(String(b.severity_level));
          return (aIdx === -1 ? 99 : aIdx) - (bIdx === -1 ? 99 : bIdx);
        });
      }

      // CVSS DESC order
      if (lower.includes('cvss_score desc')) {
        filtered.sort((a, b) => Number(b.cvss_score || 0) - Number(a.cvss_score || 0));
      }

      // Effectiveness rating DESC
      if (lower.includes('effectiveness_rating desc')) {
        filtered.sort((a, b) => Number(b.effectiveness_rating || 0) - Number(a.effectiveness_rating || 0));
      }

      // LIMIT check
      const limitMatch = lower.match(/limit\s+([0-9]+)/);
      if (limitMatch) {
        const count = parseInt(limitMatch[1], 10);
        if (!isNaN(count)) filtered = filtered.slice(0, count);
      }

      // Determine selected columns
      const selectMatch = clean.match(/select\s+(.+?)\s+from/i);
      let selectedCols: string[] = [];

      if (selectMatch && selectMatch[1].trim() !== '*') {
        const requestedCols = selectMatch[1]
          .split(',')
          .map((c) => c.trim().replace(/^.*?\./, '').trim()); // handle alias prefix
        const firstRow = filtered[0] || dataset[0] || {};
        selectedCols = requestedCols.filter((c) => c in firstRow);
      }

      if (selectedCols.length === 0) {
        selectedCols = filtered.length > 0 ? Object.keys(filtered[0]) : dataset.length > 0 ? Object.keys(dataset[0]) : [];
      }

      // Format projected rows
      const projectedRows = filtered.map((row) => {
        const out: Record<string, unknown> = {};
        for (const col of selectedCols) {
          out[col] = row[col] ?? null;
        }
        return out;
      });

      return {
        columns: selectedCols,
        rows: projectedRows,
      };
    }
  }

  // Default fallback for any SELECT 1, version(), etc.
  if (lower.includes('version')) {
    return {
      columns: ['VERSION()'],
      rows: [{ 'VERSION()': '11.4.2-MariaDB-SolarWinds-Cloud' }],
    };
  }

  return {
    columns: ['Status'],
    rows: [{ Status: 'Query executed successfully (Vercel Cloud Emulation)' }],
  };
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { sql } = body as { sql: string };

    if (!sql || typeof sql !== 'string' || sql.trim() === '') {
      return Response.json({ error: 'No SQL query provided.' }, { status: 400 });
    }

    // Safety: only allow read-only commands
    const trimmed = sql.trim().toUpperCase();
    const allowed = ['SELECT', 'SHOW', 'DESCRIBE', 'DESC', 'EXPLAIN'];
    const isAllowed = allowed.some((kw) => trimmed.startsWith(kw));

    if (!isAllowed) {
      return Response.json(
        { error: 'Only SELECT, SHOW, DESCRIBE, and EXPLAIN queries are allowed in this case study console.' },
        { status: 403 }
      );
    }

    const start = Date.now();

    // 1. Try real MariaDB first
    try {
      const rows = await query<Record<string, unknown>[]>(sql);
      const elapsed = Date.now() - start;
      const columns = Array.isArray(rows) && rows.length > 0 ? Object.keys(rows[0]) : [];
      return Response.json({
        columns,
        rows: Array.isArray(rows) ? rows : [],
        rowCount: Array.isArray(rows) ? rows.length : 0,
        executionMs: elapsed,
      });
    } catch (dbErr) {
      // 2. If MariaDB is unreachable (e.g. running on Vercel without local host network access)
      // gracefully fallback to in-memory evaluation
      console.warn('Real MariaDB unreachable, executing in-memory query:', dbErr);
      const result = executeInMemoryQuery(sql);
      const elapsed = Date.now() - start;
      return Response.json({
        columns: result.columns,
        rows: result.rows,
        rowCount: result.rows.length,
        executionMs: elapsed,
      });
    }
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return Response.json({ error: msg }, { status: 500 });
  }
}
