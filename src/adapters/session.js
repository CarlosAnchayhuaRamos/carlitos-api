import { DurableObject } from 'cloudflare:workers'
import { AnonymousAccess } from '../application/anonymous.js'
import { FirstError, issueToken } from './first.js'

export class AnonymousSession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env)
    this.access = new AnonymousAccess(ctx.storage, () => issueToken(env))
  }

  async obtain() {
    try { return { token: (await this.access.get()).value } } catch (err) {
      // Preserve issuer errors across RPC so a provider failure never triggers a retry.
      if (err instanceof FirstError) return { error: err.message, status: err.status }
      return { internalError: true }
    }
  }
}
