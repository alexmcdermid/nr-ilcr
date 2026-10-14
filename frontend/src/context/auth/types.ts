import type { MockUser } from './mockUsers'

export { ILCR_ROLES } from './mockUsers'
export type { IlcrRole, MockUser } from './mockUsers'

/**
 * The signed-in user as the SPA holds it, sourced from {@code GET /api/v1/me} (FAM is the source of
 * truth). Shape matches the backend {@code CurrentUser} contract (Story 1.1).
 */
export type AuthUser = {
  userGuid: string
  displayName: string
  email: string | null
  identityProvider: string | null
  roles: string[]
}

/** Local-dev-only role switching, present on the context only under the Mock provider. */
export type MockRoleSwitch = {
  users: MockUser[]
  currentUserId: string
  setUserId: (id: string) => void
}

/**
 * Local-dev-only "view as" override for a REAL FAM session: forces the role the SPA uses (nav + route
 * guards) without touching the backend, which still enforces the real token. Exposed by the real
 * provider only under {@code import.meta.env.DEV}, so it is absent from every deployed build.
 */
export type DevRoleSwitch = {
  override: string | null
  realRoles: string[]
  setOverride: (role: string | null) => void
}

export type AuthContextValue = {
  user: AuthUser | null
  isAuthenticated: boolean
  isLoading: boolean
  hasRole: (role: string) => boolean
  signIn: () => void | Promise<void>
  signOut: () => void | Promise<void>
  /** Only defined under the Mock provider (local dev); absent in real builds. */
  mock?: MockRoleSwitch
  /** Only defined under the real provider in local dev; absent in every deployed build. */
  devRoleSwitch?: DevRoleSwitch
}

export type LoginProvider = 'idir' | 'business-bceid'
