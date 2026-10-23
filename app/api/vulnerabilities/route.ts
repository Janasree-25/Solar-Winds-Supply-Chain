import { query } from '@/lib/db';
import { SEED_VULNERABILITIES } from '@/lib/seed-data';

export async function GET() {
  try {
    const rows = await query(`
      SELECT id, cve_id, name, cvss_score, vulnerability_type,
             affected_software, date_published, date_patched,
             exploit_available, description
      FROM vulnerabilities
      ORDER BY cvss_score DESC
    `);
    if (Array.isArray(rows) && rows.length > 0) {
      return Response.json(rows);
    }
    return Response.json(SEED_VULNERABILITIES);
  } catch (error) {
    console.warn('Vulnerabilities API DB fallback to seed data:', error);
    return Response.json(SEED_VULNERABILITIES);
  }
}
