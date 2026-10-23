import { query } from '@/lib/db';
import { SEED_INCIDENTS } from '@/lib/seed-data';

export async function GET() {
  try {
    const rows = await query(`
      SELECT
        ai.id, ai.incident_name, ai.attack_phase, ai.date_occurred,
        ai.attack_vector, ai.severity_level, ai.description, ai.impact,
        ta.name AS threat_actor_name, ta.alias AS threat_actor_alias,
        o.name AS target_org_name, o.sector AS target_org_sector
      FROM attack_incidents ai
      LEFT JOIN threat_actors ta ON ai.threat_actor_id = ta.id
      LEFT JOIN organizations o ON ai.target_org_id = o.id
      ORDER BY ai.date_occurred ASC
    `);
    if (Array.isArray(rows) && rows.length > 0) {
      return Response.json(rows);
    }
    return Response.json(SEED_INCIDENTS);
  } catch (error) {
    console.warn('Incidents API DB fallback to seed data:', error);
    return Response.json(SEED_INCIDENTS);
  }
}
