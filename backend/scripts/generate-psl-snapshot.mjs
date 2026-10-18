// One-off generator: converts the downloaded publicsuffix.org dat into
// src/psl-snapshot-data.mjs. Usage: node scripts/generate-psl-snapshot.mjs [dat-path]
//
// Exports two sets: `entries` (every rule, used to reject public-suffix roots
// as indicators) and `privateEntries` (the PRIVATE DOMAINS section only, used
// for shared-host detection — a multi-label PRIVATE parent like vercel.app
// makes a domain exact-match only, while normal registrable domains under
// ICANN suffixes such as co.uk or com.ng keep subdomain matching). Wildcard
// rules (*.ck) contribute their base entry and are recorded in
// `wildcardBases`; exception rules (!www.ck) are recorded so the excepted
// domain is not treated as a public suffix.
import { readFile, writeFile } from 'node:fs/promises';

const datPath = process.argv[2] ?? '/tmp/public_suffix_list.dat';
const raw = await readFile(datPath, 'utf8');
const version = raw.match(/^\/\/ VERSION: (.+)$/m)?.[1] ?? 'unknown';
const commit = raw.match(/^\/\/ COMMIT: (.+)$/m)?.[1] ?? 'unknown';

function toPunycode(line) {
  try { return new URL(`http://${line}`).hostname; } catch { return null; }
}

const entries = new Set();
const privateEntries = new Set();
const exceptions = new Set();
const wildcardBases = new Set();
let inPrivate = false;
for (const line of raw.split('\n')) {
  const trimmed = line.trim();
  if (trimmed.startsWith('// ===BEGIN PRIVATE DOMAINS===')) { inPrivate = true; continue; }
  if (trimmed.startsWith('// ===END PRIVATE DOMAINS===')) { inPrivate = false; continue; }
  if (!trimmed || trimmed.startsWith('//')) continue;
  if (trimmed.startsWith('!')) {
    const host = toPunycode(trimmed.slice(1));
    if (host) exceptions.add(host);
    continue;
  }
  let rule = trimmed;
  let wildcard = false;
  if (rule.startsWith('*.')) { rule = rule.slice(2); wildcard = true; }
  const host = toPunycode(rule);
  if (!host) continue;
  entries.add(host);
  if (inPrivate) privateEntries.add(host);
  if (wildcard) wildcardBases.add(host);
}

const header = `// Full Public Suffix List snapshot, pinned for the check API (issue #8).
// Source: https://publicsuffix.org/list/public_suffix_list.dat
// VERSION: ${version} (commit ${commit})
// Downloaded: 2026-10-18. Entries are normalized to punycode, lowercase.
// - entries: every rule (wildcard bases included, exceptions excluded)
// - privateEntries: rules from the PRIVATE DOMAINS section only
// - exceptions: \`!\` exception rules (these domains are NOT public suffixes)
// Regenerate with: node scripts/generate-psl-snapshot.mjs <dat-path>
export const PSL_SNAPSHOT = {
  source: 'https://publicsuffix.org/list/public_suffix_list.dat',
  version: ${JSON.stringify(version)},
  commit: ${JSON.stringify(commit)},
  downloaded: '2026-10-18',
  entries: ${JSON.stringify([...entries].sort())},
  privateEntries: ${JSON.stringify([...privateEntries].sort())},
  exceptions: ${JSON.stringify([...exceptions].sort())},
  wildcardBases: ${JSON.stringify([...wildcardBases].sort())},
};
`;
await writeFile(new URL('../src/psl-snapshot-data.mjs', import.meta.url), header);
console.log('entries:', entries.size, '| private:', privateEntries.size, '| exceptions:', exceptions.size, '| wildcards:', wildcardBases.size, '| version:', version);
console.log('spot:', ['vercel.app', 'appspot.com', 'eu.org', 'co.uk', 'com.ng'].map((d) => `${d}:all=${entries.has(d)},priv=${privateEntries.has(d)}`).join(' '));
