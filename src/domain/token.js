export function reusable(token, now) {
  return token && token.expiresAt > now + 300_000
}
