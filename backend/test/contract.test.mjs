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

test('MVP OpenAPI is separate from the disabled legacy contract and all references resolve', async () => {
  const specification = JSON.parse(await readFile(new URL('../mvp-openapi.json', import.meta.url), 'utf8'));
  assert.equal(specification.openapi, '3.1.0');
  for (const route of [
    '/v1/discord/reports', '/v1/discord/reports/status', '/v1/mvp/reports',
    '/v1/mvp/reports/{id}', '/v1/mvp/reports/{id}/triage', '/v1/mvp/reports/{id}/merge',
    '/v1/mvp/reports/{id}/publication', '/v1/mvp/incidents', '/v1/mvp/incidents/{id}',
    '/v1/mvp/incidents/{id}/publication', '/v1/mvp/proposals/{id}',
    '/v1/mvp/proposals/{id}/approval', '/v1/mvp/proposals/{id}/cancel', '/v1/mvp/notifications/outbox',
  ]) assert.ok(specification.paths[route], route);
  assert.equal(specification.paths['/v1/reports'], undefined);
  function visit(value) {
    if (!value || typeof value !== 'object') return;
    if (typeof value.$ref === 'string') {
      assert.ok(value.$ref.startsWith('#/'), value.$ref);
      assert.ok(value.$ref.slice(2).split('/').reduce((part, key) => part?.[key], specification), value.$ref);
    }
    for (const child of Object.values(value)) visit(child);
  }
  visit(specification);
});
