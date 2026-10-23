import { query } from '@/lib/db';
import { SEED_THREAT_ACTORS } from '@/lib/seed-data';

export async function GET() {
  try {
    const rows = await query(`
      SELECT id, name, alias, origin_country, sophistication_level,
             first_observed, description
      FROM threat_actors
      ORDER BY first_observed ASC
    `);
    if (Array.isArray(rows) && rows.length > 0) {
      return Response.json(rows);
    }
    return Response.json(SEED_THREAT_ACTORS);
  } catch (error) {
    console.warn('Threat actors API DB fallback to seed data:', error);
    return Response.json(SEED_THREAT_ACTORS);
  }
}
