import assert from 'node:assert/strict'
import { test } from 'node:test'
import { execFileSync } from 'node:child_process'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { Miniflare, convertV4MiniflareOptions } from 'miniflare'
import { jwtVerify, SignJWT } from 'jose'
import { AnonymousAccess } from '../src/application/anonymous.js'
import { createApp } from '../src/app.js'
import { issueToken } from '../src/adapters/first.js'

test('FIRST v1 uses GET, a signed query and Exp in milliseconds', async () => {
  const expiresAt = Date.now() + 600000
  const key = new TextEncoder().encode('test-only-issuer-secret')
  const jwt = await new SignJWT({ Exp: expiresAt }).setProtectedHeader({ alg: 'HS256' }).sign(key)
  const token = await issueToken({
    FIRST_API_VERSION: 'v1', FIRST_URL: 'https://first.invalid', FIRST_AGENT_ID: 'agent',
    FIRST_DOMAIN_ID: 'domain', FIRST_CONFIGURATION_JWT_SECRET: 'test-only-issuer-secret',
    FIRST_OPERATOR_TTL_SECONDS: 60, FIRST_SESSION_TTL_SECONDS: 7200, FIRST_TIMEOUT_MS: 3000
  }, async (url, init) => {
    assert.equal(init.method, 'GET')
    assert.equal(url.pathname, '/api/rogue/v1/auth/anonymous')
    const { payload } = await jwtVerify(url.searchParams.get('configurationJWT'), key)
    assert.equal(payload.DomainId, 'domain')
    return Response.json({ jwt })
  })
  assert.deepEqual(token, { value: jwt, expiresAt })
})

test('Worker, session RPC, real storage and limits with a simulated FIRST', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'auth-worker-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  execFileSync(process.execPath, ['node_modules/wrangler/bin/wrangler.js', 'deploy', '--dry-run', '--outdir', dir])
  const bundle = (await readdir(dir)).find(name => name.endsWith('.js'))
  const key = new TextEncoder().encode('test-only-issuer-secret')
  let calls = 0
  let mode = 'good'
  const runtime = new Miniflare(convertV4MiniflareOptions({ workers: [{ name: 'auth',
    modules: [{ type: 'ESModule', path: 'worker.js', contents: await readFile(path.join(dir, bundle), 'utf8') }], compatibilityDate: '2026-01-01',
    durableObjects: { SESSIONS: { className: 'AnonymousSession', useSQLite: true } },
    ratelimits: {
      SESSION_LIMIT: { namespace_id: '1', simple: { limit: 3, period: 60 } },
      NEW_SESSION_LIMIT: { namespace_id: '2', simple: { limit: 20, period: 60 } }
    },
    bindings: { APP_ENV: 'test', FIRST_AGENT_ID: 'agent', FIRST_DOMAIN_ID: 'domain',
      FIRST_URL: 'https://first.invalid', FIRST_CONFIGURATION_JWT_SECRET: 'test-only-issuer-secret',
      SESSION_COOKIE_SECRET: 'test-only-independent-session-signing-key',
      FIRST_OPERATOR_TTL_SECONDS: 60, FIRST_SESSION_TTL_SECONDS: 7200, FIRST_TIMEOUT_MS: 3000 },
    outboundService: async req => {
      calls++
      assert.equal(req.url, 'https://first.invalid/v2/auth/anonymous')
      assert.equal(req.method, 'POST')
      const { signedRequest } = await req.json()
      const { payload } = await jwtVerify(signedRequest, key, { algorithms: ['HS256'] })
      assert.equal(payload.AgentId, 'agent')
      assert.equal(payload.DomainId, 'domain')
      if (mode === 'error') return new Response(null, { status: 503 })
      if (mode === 'invalid') return Response.json({ jwt: 42 })
      const jwt = await new SignJWT({ jti: String(calls) }).setProtectedHeader({ alg: 'HS256' })
        .setExpirationTime('1h').sign(key)
      return Response.json({ jwt })
    }
  }] }))
  try {
    const health = await runtime.dispatchFetch('https://app.test/at-auth/v1/health')
    assert.equal(health.status, 200)
    assert.equal((await health.json()).data.status, 'Health')
    assert.ok(health.headers.get('x-correlation-id'))
    assert.equal(calls, 0)
    const post = (cookie = '') => runtime.dispatchFetch('https://app.test/at-auth/v1/auth/anonymous', {
      method: 'POST', headers: { Cookie: cookie, 'CF-Connecting-IP': '192.0.2.1' }
    })
    const first = await post()
    assert.equal(first.status, 201)
    assert.equal(first.headers.get('cache-control'), 'no-store')
    const token = (await first.json()).data.token
    const header = first.headers.get('set-cookie')
    assert.match(header, /HttpOnly/i)
    assert.match(header, /Secure/i)
    const cookie = header.split(';')[0]
    for (const reply of await Promise.all([post(cookie), post(cookie), post(cookie)])) {
      assert.equal((await reply.json()).data.token, token)
    }
    assert.equal(calls, 1)
    assert.equal((await post(cookie)).status, 429)
    assert.equal(calls, 1)
    assert.notEqual((await (await post()).json()).data.token, token)
    mode = 'error'
    const failed = await post()
    assert.equal(failed.status, 503)
    assert.equal((await failed.json()).error, 'FST-3000')
    assert.equal(calls, 3)
    mode = 'invalid'
    assert.equal((await post()).status, 502)
    assert.equal(calls, 4)
  } finally { await runtime.dispose() }
})

test('concurrent renewal at exactly five minutes shares one emission', async () => {
  let cached = { value: 'old', expiresAt: 300000 }
  let calls = 0
  const access = new AnonymousAccess({
    get: async () => cached, put: async (_, token) => { cached = token }
  }, async () => ({ value: String(++calls), expiresAt: 300001 }), () => 0)
  const tokens = await Promise.all([access.get(), access.get(), access.get()])
  assert.equal(tokens[0].value, '1')
  assert.equal((await access.get()).value, '1')
  assert.equal(calls, 1)
})

test('storage failure delivers issued token once per request', async () => {
  const broken = async () => { throw new Error('storage unavailable') }
  let calls = 0
  const access = new AnonymousAccess({ get: broken, put: broken },
    async () => ({ value: String(++calls), expiresAt: Date.now() + 3600000 }))
  assert.equal((await access.get()).value, '1')
  assert.equal(calls, 1)
})

test('invalid cookie uses IP limit before accessing FIRST or the object', async () => {
  let calls = 0
  const app = createApp(async () => ({ value: String(++calls) }))
  const env = {
    SESSION_COOKIE_SECRET: 'test-only-independent-session-signing-key',
    SESSIONS: { getByName() { throw new Error('unavailable') } },
    NEW_SESSION_LIMIT: { limit: async ({ key }) => ({ success: key === '192.0.2.1' }) }
  }
  const post = ip => app.request('https://app.test/at-auth/v1/auth/anonymous', {
    method: 'POST', headers: { Cookie: '__Host-at-anon=forged', 'CF-Connecting-IP': ip }
  }, env)
  assert.equal((await post('192.0.2.2')).status, 429)
  assert.equal(calls, 0)
  const fallback = await post('192.0.2.1')
  assert.equal(fallback.status, 201)
  assert.equal((await fallback.json()).data.token, '1')
})
