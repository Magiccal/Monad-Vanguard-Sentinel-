// One-off generator: converts the downloaded publicsuffix.org dat into
// src/psl-snapshot-data.mjs. Usage: node scripts/generate-psl-snapshot.mjs [dat-path]
import { readFile, writeFile } from 'node:fs/promises';

const datPath = process.argv[2] ?? '/tmp/public_suffix_list.dat';
const raw = await readFile(datPath, 'utf8');
const version = raw.match(/^\/\/ VERSION: (.+)$/m)?.[1] ?? 'unknown';
const commit = raw.match(/^\/\/ COMMIT: (.+)$/m)?.[1] ?? 'unknown';
const suffixes = new Set();
for (const line of raw.split('\n')) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('//')) continue;
  if (trimmed.startsWith('!') || trimmed.startsWith('*')) continue; // documented deviation
  let host;
  try { host = new URL(`http://${trimmed}`).hostname; } catch { continue; }
  if (host) suffixes.add(host);
}
const entries = [...suffixes].sort();
const header = `// Full Public Suffix List snapshot, pinned for the check API (issue #8).
// Source: https://publicsuffix.org/list/public_suffix_list.dat
// VERSION: ${version} (commit ${commit})
// Downloaded: 2026-10-18. Entries are normalized to punycode, lowercase.
// Deviations: \`!\` exception rules and \`*\` wildcard rules are omitted (the
// parent entries remain); unicode entries are stored in punycode form.
// Regenerate with: node scripts/generate-psl-snapshot.mjs <dat-path>
export const PSL_SNAPSHOT = {
  source: 'https://publicsuffix.org/list/public_suffix_list.dat',
  version: ${JSON.stringify(version)},
  commit: ${JSON.stringify(commit)},
  downloaded: '2026-10-18',
  entries: ${JSON.stringify(entries)},
};
`;
await writeFile(new URL('../src/psl-snapshot-data.mjs', import.meta.url), header);
console.log('entries:', entries.length, '| version:', version);
console.log('spot checks:', ['vercel.app', 'appspot.com', 'ngrok.io', 'eu.org', 'amazonaws.com', 'co.uk', 'co.in'].map((d) => `${d}=${entries.includes(d)}`).join(' '));
