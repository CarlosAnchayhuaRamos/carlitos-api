import { Hono } from 'hono'
import { getSignedCookie, setSignedCookie } from 'hono/cookie'
import { FirstError, issueToken } from './adapters/first.js'

const cookie = '__Host-at-anon'
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

function failure(c, status, error, message) {
  const url = new URL(c.req.url)
  const query = new URLSearchParams()
  if (url.searchParams.has('env')) query.set('env', url.searchParams.get('env'))
  const path = url.pathname + (query.size ? '?' + query : '')
  return c.json({ error, message, timestamp: new Date().toISOString(), path }, status)
}

export function createApp(issue = issueToken) {
  const app = new Hono({ strict: false })
  app.use('*', async (c, next) => {
    c.header('Cache-Control', 'no-store')
    c.header('X-Correlation-ID', crypto.randomUUID())
    await next()
  })
  app.get('/at-auth/v1/health', c => c.json({
    message: 'Service is healthy', data: { timestamp: new Date().toISOString(), status: 'Health' }
  }))
  app.post('/at-auth/v1/auth/anonymous', async c => {
    const env = c.env
    if (!env.SESSION_COOKIE_SECRET || env.SESSION_COOKIE_SECRET.length < 32) throw new Error('Invalid session configuration')
    const signed = await getSignedCookie(c, env.SESSION_COOKIE_SECRET, cookie)
    const existing = typeof signed === 'string' && uuid.test(signed)
    const limiter = existing ? env.SESSION_LIMIT : env.NEW_SESSION_LIMIT
    const key = existing ? signed : c.req.header('CF-Connecting-IP') || 'unknown'
    if (!(await limiter.limit({ key })).success) return failure(c, 429, 'HTTP-429', 'Too many requests.')
    const session = existing ? signed : crypto.randomUUID()
    if (!existing) await setSignedCookie(c, cookie, session, env.SESSION_COOKIE_SECRET, {
      path: '/', secure: true, httpOnly: true, sameSite: 'Lax'
    })
    const name = JSON.stringify([env.APP_ENV, env.FIRST_AGENT_ID, env.FIRST_DOMAIN_ID, session])
    let result
    try {
      result = await env.SESSIONS.getByName(name).obtain()
    } catch {
      result = { token: (await issue(env)).value }
    }
    if (result.internalError) throw new Error('Session configuration failed')
    if (result.error) throw new FirstError(result.status, result.error)
    return c.json({ message: 'FIRST_TOKEN retrieved successfully.', data: { token: result.token } }, 201)
  })
  app.notFound(c => failure(c, 404, 'HTTP-404', 'Not found.'))
  app.onError((err, c) => err instanceof FirstError
    ? failure(c, err.status, 'FST-3000', err.message)
    : failure(c, 500, 'UNK-5000', 'Internal server error.'))
  return app
}
