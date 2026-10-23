import { query } from '@/lib/db';
import { SEED_DEFENSE } from '@/lib/seed-data';

export async function GET() {
  try {
    const rows = await query(`
      SELECT id, measure_name, category, implementation_date,
             effectiveness_rating, description, implementing_org
      FROM defense_measures
      ORDER BY implementation_date ASC
    `);
    if (Array.isArray(rows) && rows.length > 0) {
      return Response.json(rows);
    }
    return Response.json(SEED_DEFENSE);
  } catch (error) {
    console.warn('Defense API DB fallback to seed data:', error);
    return Response.json(SEED_DEFENSE);
  }
}
