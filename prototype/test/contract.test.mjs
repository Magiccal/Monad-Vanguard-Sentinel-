import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('OpenAPI draft is valid JSON and all local references resolve', async () => {
  const specification = JSON.parse(await readFile(new URL('../openapi.json', import.meta.url), 'utf8'));
  assert.equal(specification.openapi, '3.1.0');
  const expectedRoutes = [
    '/v1/reports', '/v1/reports/{id}', '/v1/reports/{id}/review',
    '/v1/reports/{id}/evidence', '/v1/reports/{id}/check-evidence', '/v1/reports/{id}/decision',
    '/v1/reports/{id}/correction', '/v1/reports/{id}/retraction',
    '/v1/alerts', '/v1/alerts/history', '/v1/alerts/{id}', '/v1/dashboard',
    '/v1/watchlist', '/v1/watchlist/{id}/check', '/v1/watchlist/{id}/archive',
    '/v1/notifications/outbox', '/v1/contributors',
  ];
  for (const route of expectedRoutes) assert.ok(specification.paths[route], route);

  function visit(value) {
    if (!value || typeof value !== 'object') return;
    if (typeof value.$ref === 'string') {
      assert.ok(value.$ref.startsWith('#/'), value.$ref);
      const target = value.$ref.slice(2).split('/').reduce((part, key) => part?.[key], specification);
      assert.ok(target, `Unresolved reference: ${value.$ref}`);
    }
    for (const child of Object.values(value)) visit(child);
  }
  visit(specification);
});
