import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { User, UserManagerSettings } from 'oidc-client-ts'
import type * as Oidc from 'oidc-client-ts'

const mocks = vi.hoisted(() => ({
  settings: vi.fn(),
  manager: {
    getUser: vi.fn(),
    signinSilent: vi.fn(),
    signinRedirect: vi.fn(),
    signinRedirectCallback: vi.fn(),
    removeUser: vi.fn(),
  },
}))

vi.mock('oidc-client-ts', async (importOriginal) => {
  const actual = await importOriginal<typeof Oidc>()
  return {
    ...actual,
    UserManager: class {
      constructor(settings: UserManagerSettings) {
        mocks.settings(settings)
        return mocks.manager
      }
    },
  }
})

const storedUser = (secondsLeft = 300): User =>
  ({
    access_token: 'access-token',
    id_token: 'id-token',
    refresh_token: 'refresh-token',
    expires_in: secondsLeft,
    profile: { sub: 'user', azp: 'lexis' },
  }) as User

const deferred = <T>() => {
  let resolve!: (result: T) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

describe('OIDC session service', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.resetAllMocks()
    window.sessionStorage.clear()
    window.localStorage.clear()
    vi.stubEnv('VITE_OIDC_ISSUER_URI', 'https://sso.example.test/realms/standard')
    vi.stubEnv('VITE_OIDC_CLIENT_ID', 'lexis')
    vi.stubEnv('VITE_OIDC_IDIR_HINT', '')
    vi.stubEnv('VITE_OIDC_BCEID_HINT', '')
    vi.stubEnv('VITE_OIDC_SITEMINDER_LOGOUT_URL', '')
    mocks.manager.getUser.mockResolvedValue(storedUser())
    mocks.manager.signinSilent.mockResolvedValue(storedUser())
    mocks.manager.signinRedirectCallback.mockResolvedValue(storedUser())
    mocks.manager.removeUser.mockResolvedValue(undefined)
  })

  afterEach(() => vi.unstubAllEnvs())

  it('uses a public code flow and tab-scoped storage without background renewal', async () => {
    const { getUserManager } = await import('../oidc-service')
    expect(mocks.settings).not.toHaveBeenCalled()
    getUserManager()
    const settings = mocks.settings.mock.calls[0][0] as UserManagerSettings
    expect(settings).toMatchObject({
      authority: 'https://sso.example.test/realms/standard',
      client_id: 'lexis',
      response_type: 'code',
      scope: 'openid profile email',
      redirect_uri: `${window.location.origin}/authCallback`,
      post_logout_redirect_uri: `${window.location.origin}/`,
      automaticSilentRenew: false,
      loadUserInfo: false,
    })
    expect(settings.client_secret).toBeUndefined()
    expect(settings.disablePKCE).not.toBe(true)
    await settings.userStore?.set('user-probe', 'session')
    await settings.stateStore?.set('state-probe', 'state')
    expect(window.sessionStorage.getItem('oidc.user-probe')).toBe('session')
    expect(window.sessionStorage.getItem('oidc.state-probe')).toBe('state')
    expect(window.localStorage.length).toBe(0)
  })

  it('does not initialize an unconfigured identity provider', async () => {
    vi.stubEnv('VITE_OIDC_CLIENT_ID', '')
    const service = await import('../oidc-service')
    expect(service.isOidcConfigured).toBe(false)
    expect(await service.getOidcUser()).toBeNull()
    await expect(service.startOidcLogin('idir')).rejects.toThrow('not configured')
    expect(mocks.settings).not.toHaveBeenCalled()
  })

  it('selects the configured IDIR and Business BCeID providers', async () => {
    const { startOidcLogin } = await import('../oidc-service')
    await startOidcLogin('idir')
    expect(mocks.manager.signinRedirect).toHaveBeenLastCalledWith({
      state: expect.objectContaining({ returnTo: expect.any(String) }),
      extraQueryParams: { kc_idp_hint: 'azureidir' },
    })
    await startOidcLogin('business-bceid')
    expect(mocks.manager.signinRedirect).toHaveBeenLastCalledWith({
      state: expect.objectContaining({ returnTo: expect.any(String) }),
      extraQueryParams: { kc_idp_hint: 'bceidbusiness' },
    })
    vi.stubEnv('VITE_OIDC_IDIR_HINT', 'idir')
    await startOidcLogin('idir')
    expect(mocks.manager.signinRedirect).toHaveBeenLastCalledWith({
      state: expect.objectContaining({ returnTo: expect.any(String) }),
      extraQueryParams: { kc_idp_hint: 'idir' },
    })
  })

  it('does not attempt iframe login for a signed-out visitor', async () => {
    mocks.manager.getUser.mockResolvedValue(null)
    const { getOidcUser } = await import('../oidc-service')
    expect(await getOidcUser()).toBeNull()
    expect(mocks.manager.signinSilent).not.toHaveBeenCalled()
  })

  it('does not renew a fresh access token but forces renewal when extending the session', async () => {
    const { getOidcUser } = await import('../oidc-service')
    expect(await getOidcUser()).toMatchObject({ access_token: 'access-token' })
    expect(mocks.manager.signinSilent).not.toHaveBeenCalled()
    await getOidcUser({ forceRefresh: true })
    expect(mocks.manager.signinSilent).toHaveBeenCalledOnce()
  })

  it('rejects an unrenewable stored session without an iframe fallback', async () => {
    mocks.manager.getUser.mockResolvedValue({ ...storedUser(0), refresh_token: undefined })
    const { getOidcUser } = await import('../oidc-service')
    await expect(getOidcUser()).rejects.toThrow('cannot be renewed')
    expect(mocks.manager.signinSilent).not.toHaveBeenCalled()
  })

  it('removes a restored session whose refresh token SSO rejected', async () => {
    mocks.manager.getUser.mockResolvedValue(storedUser(0))
    const { restoreOidcUser } = await import('../oidc-service')
    const { ErrorResponse } = await import('oidc-client-ts')
    mocks.manager.signinSilent.mockRejectedValue(new ErrorResponse({ error: 'invalid_grant' }))
    expect(await restoreOidcUser()).toBeNull()
    expect(mocks.manager.removeUser).toHaveBeenCalledOnce()
  })

  it('keeps a restored session after a temporary failure so a reload can recover', async () => {
    mocks.manager.getUser.mockResolvedValue(storedUser(0))
    const { restoreOidcUser } = await import('../oidc-service')
    const { ErrorResponse } = await import('oidc-client-ts')
    mocks.manager.signinSilent
      .mockRejectedValueOnce(new Error('Network Error'))
      .mockRejectedValueOnce(new Error('Bad Gateway (502)'))
      .mockRejectedValueOnce(new ErrorResponse({ error: 'temporarily_unavailable' }))
      .mockRejectedValueOnce(new ErrorResponse({ error: 'server_error' }))
    for (let attempt = 0; attempt < 4; attempt += 1) {
      expect(await restoreOidcUser()).toBeNull()
    }
    expect(mocks.manager.removeUser).not.toHaveBeenCalled()
    expect(await restoreOidcUser()).toMatchObject({ access_token: 'access-token' })
  })

  it('treats only a rejected or unrenewable session as ended', async () => {
    mocks.manager.getUser.mockResolvedValue({ ...storedUser(0), refresh_token: undefined })
    const { getOidcUser, isSessionEnded } = await import('../oidc-service')
    const { ErrorResponse } = await import('oidc-client-ts')
    const unrenewable = await getOidcUser().catch((error: unknown) => error)

    expect(isSessionEnded(unrenewable)).toBe(true)
    expect(isSessionEnded(new ErrorResponse({ error: 'invalid_grant' }))).toBe(true)
    for (const temporary of [
      new TypeError('Failed to fetch'),
      new Error('Bad Gateway (502)'),
      new ErrorResponse({ error: 'temporarily_unavailable' }),
      new ErrorResponse({ error: 'server_error' }),
    ]) {
      expect(isSessionEnded(temporary)).toBe(false)
    }
  })

  it('shares one renewal between concurrent API, activity and forced-extension calls', async () => {
    mocks.manager.getUser.mockResolvedValue(storedUser(60))
    const refreshed = deferred<User>()
    mocks.manager.signinSilent.mockReturnValue(refreshed.promise)
    const { getOidcUser } = await import('../oidc-service')
    const api = getOidcUser()
    const activity = getOidcUser()
    const extension = getOidcUser({ forceRefresh: true })
    await vi.waitFor(() => expect(mocks.manager.signinSilent).toHaveBeenCalledOnce())
    const nextUser = {
      ...storedUser(),
      access_token: 'new-access',
      refresh_token: 'rotated',
    } as User
    refreshed.resolve(nextUser)
    expect(await Promise.all([api, activity, extension])).toEqual([nextUser, nextUser, nextUser])
  })

  it('does not restore credentials or return a token from a renewal finishing after logout', async () => {
    mocks.manager.getUser.mockResolvedValue(storedUser(0))
    const refreshed = deferred<User>()
    mocks.manager.signinSilent.mockReturnValue(refreshed.promise)
    const { getOidcUser, endOidcSession } = await import('../oidc-service')
    const pending = getOidcUser()
    await vi.waitFor(() => expect(mocks.manager.signinSilent).toHaveBeenCalledOnce())
    const navigate = vi.fn()
    await endOidcSession(navigate)
    expect(navigate).toHaveBeenCalledOnce()
    expect(mocks.manager.removeUser).toHaveBeenCalledOnce()
    refreshed.resolve(storedUser())
    expect(await pending).toBeNull()
    expect(mocks.manager.removeUser).toHaveBeenCalledTimes(2)
    expect(await getOidcUser()).toBeNull()
  })

  it('ends the Keycloak session with the stored ID token before clearing it', async () => {
    const { endOidcSession } = await import('../oidc-service')
    const navigate = vi.fn()
    await endOidcSession(navigate)
    const logoutUrl = new URL(navigate.mock.calls[0][0] as string)
    expect(`${logoutUrl.origin}${logoutUrl.pathname}`).toBe(
      'https://sso.example.test/realms/standard/protocol/openid-connect/logout',
    )
    expect(Object.fromEntries(logoutUrl.searchParams)).toEqual({
      client_id: 'lexis',
      post_logout_redirect_uri: `${window.location.origin}/`,
      id_token_hint: 'id-token',
    })
    expect(mocks.manager.getUser.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.manager.removeUser.mock.invocationCallOrder[0],
    )
  })

  it('logs off SiteMinder first so Business BCeID cannot sign straight back in', async () => {
    vi.stubEnv('VITE_OIDC_SITEMINDER_LOGOUT_URL', 'https://logontest7.gov.bc.ca/clp-cgi/logoff.cgi')
    const { endOidcSession } = await import('../oidc-service')
    const navigate = vi.fn()
    await endOidcSession(navigate)
    const siteminderUrl = new URL(navigate.mock.calls[0][0] as string)
    expect(`${siteminderUrl.origin}${siteminderUrl.pathname}`).toBe(
      'https://logontest7.gov.bc.ca/clp-cgi/logoff.cgi',
    )
    expect(siteminderUrl.searchParams.get('retnow')).toBe('1')
    const keycloakUrl = new URL(siteminderUrl.searchParams.get('returl') ?? '')
    expect(`${keycloakUrl.origin}${keycloakUrl.pathname}`).toBe(
      'https://sso.example.test/realms/standard/protocol/openid-connect/logout',
    )
    expect(keycloakUrl.searchParams.get('id_token_hint')).toBe('id-token')
  })

  it('clears locally and allows another attempt if sign-out fails', async () => {
    const { endOidcSession, getOidcUser } = await import('../oidc-service')
    const failedNavigation = vi.fn(() => {
      throw new Error('navigation blocked')
    })
    await expect(endOidcSession(failedNavigation)).rejects.toThrow('navigation blocked')
    expect(mocks.manager.removeUser).toHaveBeenCalled()
    expect(await getOidcUser()).toBeNull()
    const retry = vi.fn()
    await endOidcSession(retry)
    expect(retry).toHaveBeenCalledOnce()
  })

  it('consumes a callback only once across StrictMode/remount calls', async () => {
    const { completeOidcLogin } = await import('../oidc-service')
    const first = completeOidcLogin()
    const remount = completeOidcLogin()
    expect(first).toBe(remount)
    await first
    expect(mocks.manager.signinRedirectCallback).toHaveBeenCalledOnce()
  })

  it('discards a callback result if logout happened during its code exchange', async () => {
    const exchanged = deferred<User>()
    mocks.manager.signinRedirectCallback.mockReturnValue(exchanged.promise)
    const { completeOidcLogin, endOidcSession } = await import('../oidc-service')
    const pending = completeOidcLogin()
    await endOidcSession(vi.fn())
    exchanged.resolve(storedUser())
    await expect(pending).rejects.toThrow('session ended')
    expect(mocks.manager.removeUser).toHaveBeenCalled()
  })

  it('keeps an existing session when a replayed callback fails, without retrying a spent code', async () => {
    mocks.manager.signinRedirectCallback.mockRejectedValue(new Error('No matching state'))
    const { completeOidcLogin, getOidcUser } = await import('../oidc-service')
    await expect(completeOidcLogin()).rejects.toThrow('No matching state')
    await expect(completeOidcLogin()).rejects.toThrow('No matching state')
    expect(mocks.manager.signinRedirectCallback).toHaveBeenCalledOnce()
    expect(mocks.manager.removeUser).not.toHaveBeenCalled()
    expect(await getOidcUser()).toMatchObject({ access_token: 'access-token' })
  })
  it('restores only a route on this app origin from OIDC state', async () => {
    const { getOidcReturnPath } = await import('../oidc-service')
    expect(getOidcReturnPath({ state: { returnTo: '/search?year=2025' } } as User)).toBe(
      '/search?year=2025',
    )
    for (const returnTo of [
      'https://other.example.test/',
      '//other.example.test/',
      '/authCallback?code=spent',
    ]) {
      expect(getOidcReturnPath({ state: { returnTo } } as User)).toBe('/')
    }
  })
})
