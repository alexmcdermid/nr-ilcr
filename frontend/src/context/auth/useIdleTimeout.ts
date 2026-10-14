import { useEffect, useRef } from 'react'

// User activity that keeps the session alive. Pointer/keyboard/scroll/touch cover both desktop and
// tablet. Each occurrence stamps a shared "last activity" time; it does NOT re-arm a timer, so an
// active minute costs a handful of localStorage writes rather than thousands of clear/set pairs.
const ACTIVITY_EVENTS = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'] as const

// Shared across every tab of this origin. Activity in ANY tab keeps the whole session alive, and each
// tab measures idleness against this one stamp rather than its own local timer.
const STORAGE_KEY = 'nr-ilcr.last-activity'

/**
 * Sign the user out after {@code timeoutMs} of INACTIVITY (60-minute idle timeout). OIDC renews the
 * access token refreshed while the user is active, so an active session never expires; this adds
 * the idle cap for shared-workstation safety. Only armed when {@code enabled} (an authenticated
 * session).
 *
 * <p>Idleness is measured against a {@code localStorage} timestamp shared by all tabs, not a per-tab
 * timer. That fixes two bugs a bare {@code setTimeout} has: (1) a background tab wouldn't sign out a
 * user actively working in another tab of the same session, and (2) after the laptop sleeps —
 * where {@code setTimeout} does not fire reliably — the next check compares wall-clock elapsed and
 * signs out (or re-arms) correctly instead of trusting a timer that may have stalled.
 *
 * @param onIdle called once when the idle window elapses (e.g. sign out)
 * @param timeoutMs the inactivity window in milliseconds
 * @param enabled arm the timer only when true (e.g. authenticated)
 */
export function useIdleTimeout(
  onIdle: () => void,
  timeoutMs: number,
  enabled: boolean,
  onActivity?: () => void,
): void {
  // Keep the latest callback without re-arming the listeners each render.
  const onActivityRef = useRef(onActivity)
  onActivityRef.current = onActivity
  const onIdleRef = useRef(onIdle)
  onIdleRef.current = onIdle

  useEffect(() => {
    if (!enabled) {
      return undefined
    }

    let lastRenewalCheck = 0
    const markActive = () => {
      const now = Date.now()
      localStorage.setItem(STORAGE_KEY, String(now))
      if (now - lastRenewalCheck >= 30_000) {
        lastRenewalCheck = now
        onActivityRef.current?.()
      }
    }

    let timer: ReturnType<typeof setTimeout>
    const checkIdle = () => {
      const lastActivity = Number(localStorage.getItem(STORAGE_KEY) ?? '0')
      const elapsed = Date.now() - lastActivity
      if (elapsed >= timeoutMs) {
        onIdleRef.current()
        return
      }
      // Not idle yet (activity in this or another tab pushed the stamp forward, or a sleep left the
      // timer late) — re-arm for exactly the remaining window.
      timer = setTimeout(checkIdle, timeoutMs - elapsed)
    }

    ACTIVITY_EVENTS.forEach((event) =>
      window.addEventListener(event, markActive, { passive: true }),
    )
    markActive()
    timer = setTimeout(checkIdle, timeoutMs)

    return () => {
      clearTimeout(timer)
      ACTIVITY_EVENTS.forEach((event) => window.removeEventListener(event, markActive))
    }
  }, [enabled, timeoutMs])
}
