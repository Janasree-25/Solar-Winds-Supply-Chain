import { query } from '@/lib/db';
import { SEED_ORGANIZATIONS } from '@/lib/seed-data';

export async function GET() {
  try {
    const rows = await query(`
      SELECT id, name, sector, country, affected_date, breach_status,
             systems_compromised, data_exfiltrated, description
      FROM organizations
      ORDER BY affected_date ASC
    `);
    if (Array.isArray(rows) && rows.length > 0) {
      return Response.json(rows);
    }
    return Response.json(SEED_ORGANIZATIONS);
  } catch (error) {
    console.warn('Organizations API DB fallback to seed data:', error);
    return Response.json(SEED_ORGANIZATIONS);
  }
}
