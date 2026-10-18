// Full Public Suffix List snapshot (pinned) plus the two checks the indicator
// pipeline needs. Snapshot data lives in psl-snapshot-data.mjs; regenerate it
// with scripts/generate-psl-snapshot.mjs whenever the list is refreshed.
import { PSL_SNAPSHOT } from './psl-snapshot-data.mjs';

const PSL_SET = new Set(PSL_SNAPSHOT.entries);
export const PSL_SNAPSHOT_VERSION = PSL_SNAPSHOT.version;
export const PSL_SNAPSHOT_COMMIT = PSL_SNAPSHOT.commit;
export const PSL_SNAPSHOT_DOWNLOADED = PSL_SNAPSHOT.downloaded;

// True when the domain itself is a public-suffix entry and must never become
// an indicator (it would match every site under it).
export function isPublicSuffixDomain(domain) {
  return PSL_SET.has(domain);
}

// True when the parent of the domain is a multi-label public-suffix entry,
// i.e. the domain is a "full subdomain" of a suffix or shared host
// (evil.vercel.app under vercel.app, example.co.uk under co.uk). A bare-TLD
// parent (velunor-claim.xyz under xyz) is just a registrable domain, not a
// shared host. Per the issue #8 spec those shared-host subdomains are allowed
// as indicators but match exactly only, unless the proposal explicitly opts
// into subdomain matching (matchSubdomains: true).
export function isSharedHostSubdomain(domain) {
  if (typeof domain !== 'string' || !domain.includes('.')) return false;
  const parent = domain.slice(domain.indexOf('.') + 1);
  return parent.includes('.') && PSL_SET.has(parent);
}
