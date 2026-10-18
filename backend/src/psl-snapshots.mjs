// Curated offline snapshot of public-suffix and shared-host entries used to gate
// domain indicators. Phase 1 of the check API (issue #8) only needs to reject
// indicator roots that would match every site on a platform or under a ccTLD
// second level; a full 9k-line PSL mirror is intentionally not bundled here.
//
// Source: https://publicsuffix.org/ (curated subset) — pinned snapshot.
// Update policy: extend the list when reviewers need a new shared host; the
// version below changes whenever the list changes, and the check-API ETag does
// not depend on this file (it only gates proposal-time validation).
export const PSL_SNAPSHOT = {
  source: 'https://publicsuffix.org/list/public_suffix_list.dat',
  curated: true,
  version: '2026-10-18.1',
};

// Shared hosting / static-site platforms where anyone can claim a subdomain.
// A bare entry (e.g. "vercel.app") is rejected as an indicator; a full
// subdomain (e.g. "evil.vercel.app") is allowed and matches exactly only.
export const SHARED_HOST_SUFFIXES = Object.freeze([
  'vercel.app', 'netlify.app', 'github.io', 'gitlab.io', 'pages.dev',
  'workers.dev', 'web.app', 'firebaseapp.com', 'herokuapp.com', 'fly.dev',
  'onrender.com', 'render.com', 'deno.dev', 'glitch.me', 'repl.co',
  'replit.app', 'codeberg.page', 'sourcehut.page', 'surge.sh', 'bitbucket.io',
  'cloudflare.page' /* reserved, see also pages.dev */, 'blob.core.windows.net',
  'azurewebsites.net', 'cloudfront.net', 'amazonaws.com', 'firebaseapp.dev',
  'blogspot.com', 'weebly.com', 'wixsite.com', 'webnode.com', '000webhostapp.com',
]);

// Common multi-label public suffixes (ccTLD second levels). A bare entry is
// rejected as an indicator; normal registrable domains under them are fine.
export const PSL_MULTILABEL_SUFFIXES = Object.freeze([
  'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'co.jp', 'or.jp', 'ne.jp',
  'com.au', 'net.au', 'org.au', 'co.nz', 'net.nz', 'org.nz', 'com.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'co.in', 'net.in', 'org.in',
  'com.hk', 'org.hk', 'co.kr', 'or.kr', 'com.sg', 'com.my', 'co.th',
  'com.tw', 'org.tw', 'com.tr', 'com.ar', 'com.mx', 'co.za', 'com.ng',
  'co.ke', 'com.eg', 'co.il', 'com.sa', 'com.pk', 'com.bd', 'com.vn',
  'co.id', 'com.ph', 'co.in' /* keep single source of truth even if repeated */,
]);

const SHARED_SET = new Set(SHARED_HOST_SUFFIXES);
const MULTILABEL_SET = new Set(PSL_MULTILABEL_SUFFIXES);

// True when the domain itself is a public-suffix/shared-host entry that must
// never become an indicator (it would match every site under it).
export function isPublicSuffixDomain(domain) {
  return SHARED_SET.has(domain) || MULTILABEL_SET.has(domain);
}

// True when the domain is a full subdomain of a shared host (e.g.
// "evil.vercel.app"): allowed as an indicator, but matched exactly only so it
// never swallows sibling subdomains on the platform.
export function isSharedHostSubdomain(domain) {
  if (typeof domain !== 'string') return false;
  for (const suffix of SHARED_SET) {
    if (domain.endsWith(`.${suffix}`)) return true;
  }
  return false;
}
