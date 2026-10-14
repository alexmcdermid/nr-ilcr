import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { ErrorResponse } from 'oidc-client-ts'
import { server } from '@/test-setup'
import RealAuthProvider from './RealAuthProvider'
import useAuth from './useAuth'
import { emitSessionExpired } from './sessionExpiredSignal'
import type * as OidcService from '@/service/oidc-service'

const mocks = vi.hoisted(() => ({
  fetchAuthSession: vi.fn(),
  signInWithRedirect: vi.fn(),
  signOut: vi.fn(),
  removeUser: vi.fn(),
  hubHandlerRef: { current: undefined as undefined | ((e: { payload: unknown }) => void) },
}))

vi.mock('@/service/oidc-service', async (importOriginal) => ({
  AUTH_CALLBACK_PATH: '/authCallback',
  isOidcConfigured: true,
  getOidcUser: mocks.fetchAuthSession,
  completeOidcLogin: mocks.fetchAuthSession,
  startOidcLogin: mocks.signInWithRedirect,
  endOidcSession: mocks.signOut,
  getOidcReturnPath: () => '/schedule-9',
  isSessionEnded: (await importOriginal<typeof OidcService>()).isSessionEnded,
  getUserManager: () => ({
    removeUser: mocks.removeUser,
    events: {
      addUserLoaded: (callback: () => void) => {
        mocks.hubHandlerRef.current = () => callback()
      },
      removeUserLoaded: () => undefined,
    },
  }),
}))

const ME = 'http://localhost:3000/api/v1/me'

function Probe() {
  const { user, isAuthenticated, hasRole, signOut } = useAuth()
  return (
    <div>
      <span data-testid="authed">{String(isAuthenticated)}</span>
      <span data-testid="name">{user?.displayName ?? ''}</span>
      <span data-testid="admin">{String(hasRole('ILCR_ADMIN'))}</span>
      <button type="button" onClick={() => void signOut()}>
        sign out
      </button>
    </div>
  )
}

function OverrideProbe() {
  const { hasRole, devRoleSwitch } = useAuth()
  return (
    <div>
      <span data-testid="admin">{String(hasRole('ILCR_ADMIN'))}</span>
      <span data-testid="real">{(devRoleSwitch?.realRoles ?? []).join(',')}</span>
      <button type="button" onClick={() => devRoleSwitch?.setOverride('ILCR_ADMIN')}>
        view as admin
      </button>
    </div>
  )
}

function withSession(idToken: string | undefined) {
  mocks.fetchAuthSession.mockResolvedValue(idToken ? { access_token: idToken } : null)
}

beforeEach(() => {
  mocks.fetchAuthSession.mockReset()
  mocks.signInWithRedirect.mockReset().mockResolvedValue(undefined)
  mocks.signOut.mockReset().mockResolvedValue(undefined)
  mocks.removeUser.mockReset().mockResolvedValue(undefined)
  mocks.hubHandlerRef.current = undefined
  window.history.replaceState(null, '', '/')
  window.localStorage.clear()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('RealAuthProvider', () => {
  it('loads the current user from /api/v1/me once a session exists and renders children', async () => {
    withSession('id-token')
    server.use(
      http.get(ME, () =>
        HttpResponse.json({
          userGuid: 'ABC123',
          displayName: 'Alex Admin',
          email: 'alex.admin@gov.bc.ca',
          identityProvider: 'idir',
          roles: ['ILCR_ADMIN'],
        }),
      ),
    )

    render(
      <RealAuthProvider>
        <Probe />
      </RealAuthProvider>,
    )

    await waitFor(() => expect(screen.getByTestId('authed')).toHaveTextContent('true'))
    expect(screen.getByTestId('name')).toHaveTextContent('Alex Admin')
    expect(screen.getByTestId('admin')).toHaveTextContent('true')
    expect(mocks.signInWithRedirect).not.toHaveBeenCalled()
  })

  it('redirects an unauthenticated visitor to the Hosted UI, preserving the deep link', async () => {
    withSession(undefined)
    window.history.replaceState(null, '', '/schedule-1?millId=514')

    render(
      <RealAuthProvider>
        <Probe />
      </RealAuthProvider>,
    )

    await waitFor(() => expect(mocks.signInWithRedirect).toHaveBeenCalledTimes(1))
    expect(mocks.signInWithRedirect).toHaveBeenCalledWith()
    // The app is gated behind auth — children are not shown, only the sign-in chrome.
    expect(screen.getByRole('status')).toHaveTextContent('Signing in')
    expect(screen.queryByTestId('authed')).toBeNull()
  })

  it('removes a rejected stored session before starting a fresh login', async () => {
    mocks.fetchAuthSession.mockRejectedValue(new ErrorResponse({ error: 'invalid_grant' }))

    render(
      <RealAuthProvider>
        <Probe />
      </RealAuthProvider>,
    )

    await waitFor(() => expect(mocks.signInWithRedirect).toHaveBeenCalledOnce())
    expect(mocks.removeUser).toHaveBeenCalledOnce()
    expect(mocks.removeUser.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.signInWithRedirect.mock.invocationCallOrder[0],
    )
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByTestId('authed')).toBeNull()
  })

  it('does not remove stored credentials after a rejected callback exchange', async () => {
    window.history.replaceState(null, '', '/authCallback?code=spent&state=test')
    mocks.fetchAuthSession.mockRejectedValue(new ErrorResponse({ error: 'invalid_grant' }))

    render(
      <RealAuthProvider>
        <Probe />
      </RealAuthProvider>,
    )

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Connection error'))
    expect(mocks.removeUser).not.toHaveBeenCalled()
    expect(mocks.signInWithRedirect).not.toHaveBeenCalled()
    expect(window.location.pathname).toBe('/')
  })

  it('signs out through OIDC (which ends the upstream session via the logout chain)', async () => {
    withSession('id-token')
    server.use(
      http.get(ME, () =>
        HttpResponse.json({
          userGuid: 'ABC123',
          displayName: 'Sam Submitter',
          email: 's@x.ca',
          identityProvider: 'idir',
          roles: ['ILCR_SUBMITTER'],
        }),
      ),
    )
    render(
      <RealAuthProvider>
        <Probe />
      </RealAuthProvider>,
    )
    await waitFor(() => expect(screen.getByTestId('authed')).toHaveTextContent('true'))

    await userEvent.click(screen.getByRole('button', { name: 'sign out' }))
    expect(mocks.signOut).toHaveBeenCalledTimes(1)
  })

  it('restores the requested route on the customOAuthState Hub event', async () => {
    withSession('id-token')
    server.use(
      http.get(ME, () =>
        HttpResponse.json({
          userGuid: 'ABC123',
          displayName: 'Alex Admin',
          email: null,
          identityProvider: 'idir',
          roles: ['ILCR_ADMIN'],
        }),
      ),
    )
    render(
      <RealAuthProvider>
        <Probe />
      </RealAuthProvider>,
    )
    await waitFor(() => expect(mocks.hubHandlerRef.current).toBeDefined())

    window.history.replaceState(null, '', '/authCallback?code=test&state=test')
    await act(async () => {
      mocks.hubHandlerRef.current?.({ payload: { event: 'userLoaded' } })
    })
    await waitFor(() => expect(window.location.pathname).toBe('/schedule-9'))
  })

  it('shows a connection error (not a redirect loop) when the session lookup fails', async () => {
    // A rejected fetchAuthSession is a transient/OIDC failure — bouncing to the Hosted UI on a
    // valid SSO session would return straight here and loop. Render an error with Retry instead.
    mocks.fetchAuthSession.mockRejectedValue(new Error('no session'))

    render(
      <RealAuthProvider>
        <Probe />
      </RealAuthProvider>,
    )

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Connection error'))
    expect(mocks.signInWithRedirect).not.toHaveBeenCalled()
    expect(mocks.removeUser).not.toHaveBeenCalled()
  })

  it('shows a connection error and retries (no loop) when /me fails with 5xx', async () => {
    withSession('id-token')
    server.use(http.get(ME, () => new HttpResponse(null, { status: 500 })))

    render(
      <RealAuthProvider>
        <Probe />
      </RealAuthProvider>,
    )

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('temporarily unavailable'),
    )
    expect(mocks.signInWithRedirect).not.toHaveBeenCalled()

    // Retry re-attempts /me; a now-healthy backend authenticates the user.
    server.use(
      http.get(ME, () =>
        HttpResponse.json({
          userGuid: 'ABC123',
          displayName: 'Alex Admin',
          email: null,
          identityProvider: 'idir',
          roles: ['ILCR_ADMIN'],
        }),
      ),
    )
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByTestId('authed')).toHaveTextContent('true'))
  })

  it('shows access-denied with sign-out (not a loop) when /me forbids the user (403)', async () => {
    withSession('id-token')
    server.use(http.get(ME, () => new HttpResponse(null, { status: 403 })))

    render(
      <RealAuthProvider>
        <Probe />
      </RealAuthProvider>,
    )

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Access denied'))
    expect(mocks.signInWithRedirect).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(mocks.signOut).toHaveBeenCalledTimes(1)
  })

  it('ends the session when SSO rejects the refresh token', async () => {
    withSession('id-token')
    server.use(
      http.get(ME, () =>
        HttpResponse.json({
          userGuid: 'ABC123',
          displayName: 'Alex Admin',
          email: null,
          identityProvider: 'idir',
          roles: ['ILCR_ADMIN'],
        }),
      ),
    )
    render(
      <RealAuthProvider>
        <Probe />
      </RealAuthProvider>,
    )
    await waitFor(() => expect(screen.getByTestId('authed')).toHaveTextContent('true'))

    await act(async () => emitSessionExpired())
    expect(mocks.signOut).toHaveBeenCalledOnce()
    expect(screen.getByRole('status')).toHaveTextContent('Signing out')
    expect(mocks.signInWithRedirect).not.toHaveBeenCalled()
  })

  it('lets local dev override the viewed role (frontend only — real roles preserved)', async () => {
    withSession('id-token')
    server.use(
      http.get(ME, () =>
        HttpResponse.json({
          userGuid: 'ABC123',
          displayName: 'Sam Submitter',
          email: null,
          identityProvider: 'idir',
          roles: ['ILCR_SUBMITTER'],
        }),
      ),
    )
    render(
      <RealAuthProvider>
        <OverrideProbe />
      </RealAuthProvider>,
    )
    await waitFor(() => expect(screen.getByTestId('admin')).toHaveTextContent('false'))

    await userEvent.click(screen.getByRole('button', { name: 'view as admin' }))

    // The SPA now treats the user as admin, but the real token roles are unchanged (backend still 403s).
    await waitFor(() => expect(screen.getByTestId('admin')).toHaveTextContent('true'))
    expect(screen.getByTestId('real')).toHaveTextContent('ILCR_SUBMITTER')
  })
})
