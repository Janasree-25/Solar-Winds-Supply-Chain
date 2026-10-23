import { query } from '@/lib/db';
import { SEED_STATS } from '@/lib/seed-data';

interface StatsRow {
  total_organizations: number;
  total_vulnerabilities: number;
  total_incidents: number;
  avg_cvss: number;
}

export async function GET() {
  try {
    const rows = await query<StatsRow[]>(`
      SELECT
        (SELECT COUNT(*) FROM organizations) AS total_organizations,
        (SELECT COUNT(*) FROM vulnerabilities) AS total_vulnerabilities,
        (SELECT COUNT(*) FROM attack_incidents) AS total_incidents,
        (SELECT ROUND(AVG(cvss_score), 1) FROM vulnerabilities) AS avg_cvss
    `);
    if (rows && rows.length > 0 && rows[0].total_organizations !== null) {
      return Response.json(rows[0]);
    }
    return Response.json(SEED_STATS);
  } catch (error) {
    console.warn('Stats API DB fallback to seed data:', error);
    return Response.json(SEED_STATS);
  }
}
