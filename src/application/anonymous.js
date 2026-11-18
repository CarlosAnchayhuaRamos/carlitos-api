import { reusable } from '../domain/token.js'

// Storage and issuer are ports supplied by the runtime.
export class AnonymousAccess {
  constructor(storage, issue, now = Date.now) {
    this.storage = storage
    this.issue = issue
    this.now = now
  }

  get() {
    this.pending ??= this.resolve().finally(() => { this.pending = undefined })
    return this.pending
  }

  async resolve() {
    let cached
    try { cached = await this.storage.get('token') } catch { /* Issue directly. */ }
    if (reusable(cached, this.now())) return cached
    const token = await this.issue()
    if (reusable(token, this.now())) {
      try { await this.storage.put('token', token) } catch { /* Deliver the successful issuance. */ }
    }
    return token
  }
}
