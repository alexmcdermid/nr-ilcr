export type AppRuntimeConfig = {
  mockUser?: boolean
  appEnv?: string
  oidcIssuerUri?: string
  oidcClientId?: string
  oidcIdirHint?: string
  oidcBceidHint?: string
  oidcSiteminderLogoutUrl?: string
  idleTimeoutMinutes?: number
  famClientId?: string
}

declare global {
  interface Window {
    appConfig?: AppRuntimeConfig
  }
}

export function getAppRuntimeConfig(): AppRuntimeConfig | undefined {
  return typeof window === 'undefined' ? undefined : window.appConfig
}

function isLocalHost(): boolean {
  if (typeof window === 'undefined') return false
  const host = window.location.hostname
  return (
    ['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]'].includes(host) ||
    host.endsWith('.localhost')
  )
}

// Mock authentication needs both a runtime opt-in and a local browser origin.
export function isMockAuth(): boolean {
  return getAppRuntimeConfig()?.mockUser === true && isLocalHost()
}

const readOidcSetting = (field: keyof AppRuntimeConfig, viteKey: string): string | undefined => {
  const runtime = getAppRuntimeConfig()?.[field]
  return typeof runtime === 'string' && runtime.trim() ? runtime.trim() : import.meta.env[viteKey]
}

export const env = {
  mockUser: isMockAuth(),
  appEnv: getAppRuntimeConfig()?.appEnv ?? 'dev',
  isDevelopment: import.meta.env.DEV,
  isProduction: import.meta.env.PROD,
  idleTimeoutMs: (getAppRuntimeConfig()?.idleTimeoutMinutes ?? 60) * 60_000,
  get VITE_OIDC_ISSUER_URI() {
    return readOidcSetting('oidcIssuerUri', 'VITE_OIDC_ISSUER_URI')
  },
  get VITE_OIDC_CLIENT_ID() {
    return readOidcSetting('oidcClientId', 'VITE_OIDC_CLIENT_ID')
  },
  get VITE_OIDC_IDIR_HINT() {
    return readOidcSetting('oidcIdirHint', 'VITE_OIDC_IDIR_HINT')
  },
  get VITE_OIDC_BCEID_HINT() {
    return readOidcSetting('oidcBceidHint', 'VITE_OIDC_BCEID_HINT')
  },
  get VITE_OIDC_SITEMINDER_LOGOUT_URL() {
    return (
      readOidcSetting('oidcSiteminderLogoutUrl', 'VITE_OIDC_SITEMINDER_LOGOUT_URL') ??
      (getAppRuntimeConfig()?.appEnv === 'prod'
        ? 'https://logon7.gov.bc.ca/clp-cgi/logoff.cgi'
        : 'https://logontest7.gov.bc.ca/clp-cgi/logoff.cgi')
    )
  },
}
