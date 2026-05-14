import { Router, Request, Response } from 'express';

const router = Router();

/**
 * Source of truth: Open Knowledge Foundation's Harmonized System dataset.
 * Contains every WCO HS code at chapter (2), heading (4), and subheading (6) levels.
 * Public domain, ~850KB, ~5,500 entries.
 *
 * We fetch it once at server start (lazy on first request), keep it in memory,
 * and never hit the network again until the server restarts.
 */
const DATASET_URL =
  'https://raw.githubusercontent.com/datasets/harmonized-system/master/data/harmonized-system.csv';

let datasetPromise: Promise<Map<string, string>> | null = null;

function parseCsvLine(line: string): string[] {
  const result: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      result.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  result.push(cur);
  return result;
}

async function loadDataset(): Promise<Map<string, string>> {
  const started = Date.now();
  console.log('[hs] downloading HS dataset…');
  const res = await fetch(DATASET_URL);
  if (!res.ok) throw new Error(`Dataset download failed: HTTP ${res.status}`);
  const text = await res.text();

  const map = new Map<string, string>();
  const lines = text.split(/\r?\n/);
  // Header: section,hscode,description,parent,level
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const parts = parseCsvLine(line);
    if (parts.length < 3) continue;
    const code = parts[1].trim();
    const desc = parts[2].trim();
    if (code && desc) map.set(code, desc);
  }
  console.log(`[hs] dataset ready: ${map.size} entries (${Date.now() - started}ms)`);
  return map;
}

function getDataset(): Promise<Map<string, string>> {
  if (!datasetPromise) {
    datasetPromise = loadDataset().catch(err => {
      // Allow retry on next request if the first fetch failed
      datasetPromise = null;
      throw err;
    });
  }
  return datasetPromise;
}

// Kick off the download immediately at startup so the first user request is fast.
getDataset().catch(err => console.error('[hs] initial dataset load failed:', err.message));

/**
 * Look up `code` with progressive fallback: exact → 4-digit heading → 2-digit chapter.
 * Also returns the level matched ("subheading" | "heading" | "chapter") so the UI can
 * label the result properly.
 */
function lookup(
  code: string,
  dataset: Map<string, string>
): { description: string; matchedCode: string; level: 'subheading' | 'heading' | 'chapter' } | null {
  const cleaned = code.replace(/\D/g, '');

  const tries: Array<{ code: string; level: 'subheading' | 'heading' | 'chapter' }> = [];
  if (cleaned.length >= 6) tries.push({ code: cleaned.slice(0, 6), level: 'subheading' });
  if (cleaned.length >= 4) tries.push({ code: cleaned.slice(0, 4), level: 'heading' });
  if (cleaned.length >= 2) tries.push({ code: cleaned.slice(0, 2), level: 'chapter' });

  for (const t of tries) {
    const desc = dataset.get(t.code);
    if (desc) return { description: desc, matchedCode: t.code, level: t.level };
  }
  return null;
}

/**
 * GET /api/hs/lookup?code=850760
 *   →  { code, description, matchedCode, level } | { code, description: null }
 */
router.get('/lookup', async (req: Request, res: Response) => {
  const raw = String(req.query.code ?? '').replace(/\D/g, '').slice(0, 6);
  if (raw.length < 2) {
    return res.status(400).json({ error: 'code must be at least 2 digits' });
  }

  try {
    const dataset = await getDataset();
    const result = lookup(raw, dataset);
    if (!result) {
      return res.json({ code: raw, description: null });
    }
    console.log(`[hs] ${raw} → ${result.matchedCode} (${result.level}): ${result.description}`);
    return res.json({
      code: raw,
      description: result.description,
      matchedCode: result.matchedCode,
      level: result.level,
    });
  } catch (err) {
    console.error('[hs] lookup error:', err);
    return res.status(503).json({ error: 'HS dataset unavailable' });
  }
});

export default router;
