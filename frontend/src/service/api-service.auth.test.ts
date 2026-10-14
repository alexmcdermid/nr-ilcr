import { beforeEach, describe, expect, it, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@/test-setup'
const mocks = vi.hoisted(() => ({ user: vi.fn(), expired: vi.fn(), ended: false }))
vi.mock('@/env', () => ({ isMockAuth: () => false }))
vi.mock('@/service/oidc-service', () => ({
  getOidcUser: mocks.user,
  isSessionEnded: () => mocks.ended,
}))
vi.mock('@/context/auth/sessionExpiredSignal', () => ({ emitSessionExpired: mocks.expired }))
const PROBE = 'http://localhost:3000/api/v1/probe'
async function client() {
  return (await import('./api-service')).default.getAxiosInstance()
}
beforeEach(() => {
  vi.clearAllMocks()
  mocks.ended = false
  mocks.user.mockResolvedValue({ access_token: 'ACCESS-TOKEN', id_token: 'ID-TOKEN' })
})
describe('CSS API authentication', () => {
  it('sends the access token, never the ID token', async () => {
    let authorization: string | null = null
    server.use(
      http.get(PROBE, ({ request }) => {
        authorization = request.headers.get('authorization')
        return HttpResponse.json({})
      }),
    )
    await (await client()).get('/v1/probe')
    expect(authorization).toBe('Bearer ACCESS-TOKEN')
  })
  it('refreshes once and retries a rejected request', async () => {
    let calls = 0
    server.use(
      http.get(PROBE, () =>
        ++calls === 1 ? new HttpResponse(null, { status: 401 }) : HttpResponse.json({}),
      ),
    )
    await (await client()).get('/v1/probe')
    expect(calls).toBe(2)
    expect(mocks.user).toHaveBeenCalledWith({ forceRefresh: true })
    expect(mocks.expired).not.toHaveBeenCalled()
  })
  it('ends a session whose refresh token is rejected', async () => {
    mocks.ended = true
    mocks.user.mockImplementation((options) =>
      options?.forceRefresh
        ? Promise.reject(new Error('invalid_grant'))
        : Promise.resolve({ access_token: 'ACCESS-TOKEN' }),
    )
    server.use(http.get(PROBE, () => new HttpResponse(null, { status: 401 })))
    await expect((await client()).get('/v1/probe')).rejects.toBeDefined()
    expect(mocks.expired).toHaveBeenCalledOnce()
  })
  it('preserves the session on a temporary refresh outage', async () => {
    mocks.user.mockImplementation((options) =>
      options?.forceRefresh
        ? Promise.reject(new Error('temporarily unavailable'))
        : Promise.resolve({ access_token: 'ACCESS-TOKEN' }),
    )
    server.use(http.get(PROBE, () => new HttpResponse(null, { status: 401 })))
    await expect((await client()).get('/v1/probe')).rejects.toBeDefined()
    expect(mocks.expired).not.toHaveBeenCalled()
  })
  it('does not loop when a refreshed token is also rejected', async () => {
    let calls = 0
    server.use(
      http.get(PROBE, () => {
        calls++
        return new HttpResponse(null, { status: 401 })
      }),
    )
    await expect((await client()).get('/v1/probe')).rejects.toBeDefined()
    expect(calls).toBe(2)
  })
})
