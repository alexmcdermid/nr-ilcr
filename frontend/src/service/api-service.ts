import type { AxiosInstance, AxiosResponse, InternalAxiosRequestConfig } from 'axios'
import axios from 'axios'
import { getOidcUser, isSessionEnded } from '@/service/oidc-service'
import { emitSessionExpired } from '@/context/auth/sessionExpiredSignal'
import { isMockAuth } from '@/env'
import { MOCK_USER_STORAGE_KEY, findMockUser } from '@/context/auth/mockUsers'

function mockUserGroups(): string {
  try {
    return findMockUser(localStorage.getItem(MOCK_USER_STORAGE_KEY)).roles.join(',')
  } catch {
    return ''
  }
}

type RetriableConfig = InternalAxiosRequestConfig & { retriedAfterRefresh?: boolean }

class APIService {
  private readonly client: AxiosInstance
  constructor() {
    this.client = axios.create({ baseURL: '/api', headers: { 'Content-Type': 'application/json' } })
    this.client.interceptors.request.use(async (config) => {
      if (isMockAuth()) {
        const groups = mockUserGroups()
        if (groups) config.headers.set('X-Mock-Groups', groups)
        return config
      }
      try {
        const user = await getOidcUser()
        if (user?.access_token) config.headers.set('Authorization', `Bearer ${user.access_token}`)
      } catch (error) {
        if (isSessionEnded(error)) emitSessionExpired()
        return Promise.reject(error)
      }
      return config
    })
    this.client.interceptors.response.use(
      (response: AxiosResponse) => response,
      async (error: unknown) => {
        if (!axios.isAxiosError(error)) return Promise.reject(error)
        const original = error.config as RetriableConfig | undefined
        if (
          isMockAuth() ||
          error.response?.status !== 401 ||
          !original ||
          original.retriedAfterRefresh
        )
          return Promise.reject(error)
        original.retriedAfterRefresh = true
        try {
          const user = await getOidcUser({ forceRefresh: true })
          if (user?.access_token) return this.client.request(original)
          emitSessionExpired()
        } catch (renewalError) {
          // A temporary SSO outage must preserve the session and the user's form.
          if (isSessionEnded(renewalError)) emitSessionExpired()
        }
        return Promise.reject(error)
      },
    )
  }
  public getAxiosInstance(): AxiosInstance {
    return this.client
  }
}
export default new APIService()
