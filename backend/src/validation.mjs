const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const TRANSACTION_HASH = /^0x[0-9a-fA-F]{64}$/;

// Return null for invalid input so web and bot adapters can share these checks.
export function normalizeAddress(value) {
  return typeof value === 'string' && ADDRESS.test(value) ? value.toLowerCase() : null;
}

export function normalizeTransactionHash(value) {
  return typeof value === 'string' && TRANSACTION_HASH.test(value) ? value.toLowerCase() : null;
}

// This policy applies to evidence sources, not to reported suspicious URLs.
export function inspectPublicSourceUrl(value) {
  if (typeof value !== 'string') return { error: 'invalid' };
  let url;
  try { url = new URL(value); } catch { return { error: 'invalid' }; }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.href.length > 2048) {
    return { error: 'unsafe' };
  }
  return { url: url.href };
}

const SEED_LABEL = /(?:\b(?:seed\s+phrase|recovery\s+phrase|mnemonic(?:\s+phrase)?)\b|助记词|助記詞)\s*(?::|：|=|\bis\b|是)\s*([a-z]+(?:[ \t]+[a-z]+){11,23})(?=$|[.\n;])/im;
const PRIVATE_KEY_LABEL = /(?:\b(?:private|secret)\s+key\b|私钥|私鑰)\s*(?::|：|=|\bis\b|是)\s*(?:0x)?[0-9a-f]{64}\b/i;
const EXTENDED_PRIVATE_KEY = /\b(?:xprv|yprv|zprv|tprv)[1-9A-HJ-NP-Za-km-z]{100,}\b/;

// Conservative checks: an unlabeled 32-byte hex string may be a transaction hash.
export function detectSensitiveMaterial(value) {
  if (typeof value !== 'string') return null;
  if (PRIVATE_KEY_LABEL.test(value) || EXTENDED_PRIVATE_KEY.test(value)) return 'private_key';
  const phrase = SEED_LABEL.exec(value)?.[1];
  if (phrase && [12, 15, 18, 21, 24].includes(phrase.trim().split(/[ \t]+/).length)) return 'seed_phrase';
  return null;
}
