import { afterEach, describe, expect, it } from 'vitest'
import { isMockAuth } from './env'

describe('isMockAuth', () => {
  afterEach(() => {
    // Restore the suite-wide default set in test-setup.
    window.appConfig = { mockUser: true }
  })

  it('is true when the runtime config opts into mock on a local host', () => {
    window.appConfig = { mockUser: true }
    expect(isMockAuth()).toBe(true)
  })

  it('is false when the runtime config does not opt into mock (deployed default)', () => {
    window.appConfig = { mockUser: false }
    expect(isMockAuth()).toBe(false)
  })

  it('is false when there is no runtime config at all', () => {
    window.appConfig = undefined
    expect(isMockAuth()).toBe(false)
  })
})
