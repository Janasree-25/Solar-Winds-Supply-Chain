import { query } from '@/lib/db';
import { SEED_SOFTWARE } from '@/lib/seed-data';

export async function GET() {
  try {
    const rows = await query(`
      SELECT id, product_name, version, release_date, is_compromised,
             malware_embedded, vulnerability_type, cve_id
      FROM software_versions
      ORDER BY is_compromised DESC, release_date ASC
    `);
    if (Array.isArray(rows) && rows.length > 0) {
      return Response.json(rows);
    }
    return Response.json(SEED_SOFTWARE);
  } catch (error) {
    console.warn('Software API DB fallback to seed data:', error);
    return Response.json(SEED_SOFTWARE);
  }
}
