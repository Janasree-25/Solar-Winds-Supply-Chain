import { query } from '@/lib/db';


export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { sql } = body as { sql: string };

    if (!sql || typeof sql !== 'string' || sql.trim() === '') {
      return Response.json({ error: 'No SQL query provided.' }, { status: 400 });
    }

    // Safety: only allow SELECT / SHOW / DESCRIBE queries (read-only)
    const trimmed = sql.trim().toUpperCase();
    const allowed = ['SELECT', 'SHOW', 'DESCRIBE', 'DESC', 'EXPLAIN'];
    const isAllowed = allowed.some((kw) => trimmed.startsWith(kw));

    if (!isAllowed) {
      return Response.json(
        { error: 'Only SELECT, SHOW, DESCRIBE, and EXPLAIN queries are allowed.' },
        { status: 403 }
      );
    }

    const start = Date.now();
    const rows = await query<Record<string, unknown>[]>(sql);
    const elapsed = Date.now() - start;

    const columns = rows.length > 0 ? Object.keys(rows[0]) : [];

    return Response.json({
      columns,
      rows,
      rowCount: rows.length,
      executionMs: elapsed,
    });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return Response.json({ error: msg }, { status: 500 });
  }
}
