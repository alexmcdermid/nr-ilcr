type Listener = () => void

const listeners = new Set<Listener>()

/**
 * Bridges the plain axios module (request.ts) into RealAuthProvider (a React
 * component) so a real 401 from our backend — the one unambiguous signal that
 * the session is actually dead — can trigger a real sign-out.
 */
export function onSessionExpired(listener: Listener): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function emitSessionExpired(): void {
  listeners.forEach((listener) => listener())
}
