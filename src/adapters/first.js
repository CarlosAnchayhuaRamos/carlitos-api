import { SignJWT, decodeJwt, decodeProtectedHeader } from 'jose'
import { z } from 'zod'

const responseSchema = z.object({ jwt: z.string().min(1) })
const configSchema = z.object({
  FIRST_API_VERSION: z.enum(['v1', 'v2']).default('v2'),
  FIRST_URL: z.url({ protocol: /^https$/ }),
  FIRST_AGENT_ID: z.string().min(1),
  FIRST_DOMAIN_ID: z.string().min(1),
  FIRST_CONFIGURATION_JWT_SECRET: z.string().min(1),
  FIRST_OPERATOR_TTL_SECONDS: z.coerce.number().int().positive(),
  FIRST_SESSION_TTL_SECONDS: z.coerce.number().int().positive(),
  FIRST_TIMEOUT_MS: z.coerce.number().int().positive()
})

export class FirstError extends Error {
  constructor(status, message) { super(message); this.status = status }
}

export async function issueToken(env, send = fetch) {
  const config = configSchema.parse(env)
  const now = Date.now()
  const seconds = Math.floor(now / 1000)
  const signedRequest = await new SignJWT({ AgentId: config.FIRST_AGENT_ID, DomainId: config.FIRST_DOMAIN_ID })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' }).setIssuedAt(seconds)
    .setExpirationTime(seconds + config.FIRST_OPERATOR_TTL_SECONDS)
    .sign(new TextEncoder().encode(config.FIRST_CONFIGURATION_JWT_SECRET))
  const signal = AbortSignal.timeout(config.FIRST_TIMEOUT_MS)
  let response
  try {
    const base = config.FIRST_URL.replace(/\/+$/, '')
    if (config.FIRST_API_VERSION === 'v1') {
      const url = new URL(base + '/api/rogue/v1/auth/anonymous')
      url.searchParams.set('configurationJWT', signedRequest)
      response = await send(url, { method: 'GET', redirect: 'manual', signal })
    } else {
      response = await send(base + '/v2/auth/anonymous', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, redirect: 'manual',
        body: JSON.stringify({ signedRequest }), signal
      })
    }
  } catch {
    throw new FirstError(422, signal.aborted ? 'FIRST request timed out or cancelled.' : 'Unable to obtain FIRST token.')
  }
  if (!response.ok) throw new FirstError(response.status >= 400 ? response.status : 502, 'Unable to obtain FIRST token.')
  let jwt
  try { ({ jwt } = responseSchema.parse(await response.json())) } catch {
    if (signal.aborted) throw new FirstError(422, 'FIRST request timed out or cancelled.')
    throw new FirstError(502, 'Invalid FIRST response.')
  }
  let expiresAt
  try {
    decodeProtectedHeader(jwt)
    const claims = decodeJwt(jwt)
    // FIRST v1 uses Exp in Unix milliseconds. Standard exp is in seconds.
    if (claims.exp === undefined && config.FIRST_API_VERSION === 'v1') {
      expiresAt = claims.Exp
    } else if (typeof claims.exp === 'number') {
      expiresAt = claims.exp * 1000
    }
  } catch { throw new FirstError(502, 'Invalid FIRST token.') }
  // FIRST supplied this token over TLS. The claim only bounds cache lifetime.
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw new FirstError(502, 'Invalid FIRST expiration.')
  return { value: jwt, expiresAt: Math.min(expiresAt, now + config.FIRST_SESSION_TTL_SECONDS * 1000) }
}
