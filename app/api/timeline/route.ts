import { query } from '@/lib/db';
import { SEED_TIMELINE } from '@/lib/seed-data';

export async function GET() {
  try {
    const rows = await query(`
      SELECT id, event_date, event_title, event_type, description, significance_level
      FROM timeline_events
      ORDER BY event_date ASC
    `);
    if (Array.isArray(rows) && rows.length > 0) {
      return Response.json(rows);
    }
    return Response.json(SEED_TIMELINE);
  } catch (error) {
    console.warn('Timeline API DB fallback to seed data:', error);
    return Response.json(SEED_TIMELINE);
  }
}
