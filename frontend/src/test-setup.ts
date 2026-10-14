import '@testing-library/jest-dom'
import { afterAll, afterEach, beforeAll, beforeEach } from 'vitest'
import { setupServer } from 'msw/node'
import { http, HttpResponse } from 'msw'

class ResizeObserverMock implements ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

globalThis.ResizeObserver = ResizeObserverMock

// Tests run under the Mock auth provider (no Cognito). jsdom's host is localhost, so this runtime
// config satisfies the isMockAuth() double-gate and keeps the auth seam on the mock path.
window.appConfig = { mockUser: true }

// jsdom doesn't implement scrollTo; TanStack Router calls it on navigation (scroll restoration). Stub
// it so router-driven tests don't emit "Not implemented" noise.
globalThis.scrollTo = () => {}

// jsdom doesn't implement window.matchMedia; LayoutProvider uses it to decide whether the side nav
// starts expanded (Carbon's `lg` breakpoint). The stub reports a NARROW viewport by default, so any
// test that doesn't care keeps the pre-#316 collapsed shell. Tests that do care call
// setLargeViewport(true) before rendering, or crossViewportBreakpoint() to simulate a resize.
//
// The stub is deliberately query-AWARE. An earlier version answered every query with the viewport
// flag, which meant `setLargeViewport(true)` also told Carbon that `(prefers-color-scheme: dark)` and
// `(max-width: 20rem)` matched — Carbon's Theme, Tabs, PageHeader and PaginationNav all call
// matchMedia, so a future test could have silently exercised the wrong branch and asserted nothing.
const LARGE_VIEWPORT_QUERY = '(min-width: 66rem)'

type MediaQueryChangeListener = (event: MediaQueryListEvent) => void

let isLargeViewport = false
// Keyed by query so a crossing notifies only the listeners that registered for THAT query.
const viewportListeners = new Set<{ query: string; listener: MediaQueryChangeListener }>()

function matchesQuery(query: string): boolean {
  return query === LARGE_VIEWPORT_QUERY ? isLargeViewport : false
}

/** Set the viewport BEFORE rendering. Throws if listeners already exist — see crossViewportBreakpoint. */
export function setLargeViewport(matches: boolean): void {
  if (viewportListeners.size > 0) {
    throw new Error(
      'setLargeViewport() was called after a component subscribed to matchMedia, where it is a silent ' +
        'no-op for already-mounted consumers. Call it before render(), or use crossViewportBreakpoint() ' +
        'to simulate a resize.',
    )
  }
  isLargeViewport = matches
}

/** Simulate the viewport crossing Carbon's `lg` breakpoint, notifying only that query's listeners. */
export function crossViewportBreakpoint(matches: boolean): void {
  isLargeViewport = matches
  for (const { query, listener } of viewportListeners) {
    if (query === LARGE_VIEWPORT_QUERY) {
      listener({ matches } as MediaQueryListEvent)
    }
  }
}

/** Registered-listener count, so a test can prove the provider actually unsubscribes on unmount. */
export function activeViewportListenerCount(): number {
  return viewportListeners.size
}

window.matchMedia = ((query: string) => ({
  // A getter, not a snapshot: real MediaQueryList objects report the CURRENT state, so code that
  // re-reads `mql.matches` after a crossing (rather than trusting `event.matches`) must see the new
  // value. A snapshot here would make a correct production fix look like a test failure.
  get matches() {
    return matchesQuery(query)
  },
  media: query,
  onchange: null,
  addEventListener: (_type: string, listener: MediaQueryChangeListener) => {
    viewportListeners.add({ query, listener })
  },
  removeEventListener: (_type: string, listener: MediaQueryChangeListener) => {
    for (const entry of viewportListeners) {
      if (entry.listener === listener && entry.query === query) {
        viewportListeners.delete(entry)
      }
    }
  },
  // Deprecated MediaQueryList API — present so the object type-checks, unused by the app.
  addListener: () => {},
  removeListener: () => {},
  dispatchEvent: () => false,
})) as typeof window.matchMedia

// jsdom doesn't implement Element.scrollIntoView; Carbon's Dropdown calls it on the highlighted item
// when an open dropdown already has a selection, throwing inside its effect. Stub it so editing a
// page/sample with a pre-selected code value can open its dropdowns in tests.
Element.prototype.scrollIntoView = () => {}

const users = [
  {
    id: 1,
    name: 'ILCR Developer',
    email: 'ilcr.dev@gov.bc.ca',
  },
]

// Canonical Schedule 1 document (matches the Story 1.2 backend doc / V3 seed) for the default handler.
const schedule1Doc = {
  millId: 514,
  year: 2021,
  trackStatus: 'D',
  editable: true,
  crownVolume: 12345,
  schedule3CrownVolume: 54321,
  revisionCount: 3,
  comments: 'Seed comment for 514/2021',
  lineItems: [{ costItemCode: 12, volume: 1000, cost: 50000, perUnit: 50.0 }],
  silviculture: {
    actualSpent: { costItemCode: 1, volume: 500, cost: 20000, perUnit: 40.0 },
    accruedLessActual: null,
    lessAdmin: null,
    total: null,
  },
  forestMgmtAdminCost: 600000,
  lessSilvAdminCost: 150000,
  otherCosts: { volume: 8000, costSubtotal: 24000, perUnit: 3.0, count: 2 },
  warnings: [],
}

// Default Schedule 8 dropdown option lists (code + description) for the page editor, which fetches
// GET /v1/schedule8/options on mount — schedule-8 tests would trip onUnhandledRequest: 'error'
// without this. Descriptions mirror the *Label values on the canonical page fixtures so a seeded
// page's selected option renders the same text. Tests override via server.use(...) as needed.
const schedule8Options = {
  supportCentres: [
    { code: 'SC1', description: 'Support Centre 1' },
    { code: 'SC2', description: 'Support Centre 2' },
  ],
  regions: [{ code: 'R1', description: 'Region 1' }],
  becZones: [{ code: 'BZ1', description: 'BEC 1' }],
  tsaNumbers: [{ code: 'TSA1', description: 'TSA 1' }],
  tflNumbers: [{ code: 'TFL1', description: 'TFL One' }],
  supplyBlocks: [
    { code: 'A', description: 'Block A' },
    { code: 'B', description: 'Block B' },
  ],
  skidTypes: [
    { code: 'NA', description: 'Not Applicable' },
    { code: 'HO', description: 'Horse' },
  ],
  additionCostItems: [
    { code: '82', description: 'Bridge Construction' },
    { code: '83', description: 'Road Construction' },
  ],
  deductionCostItems: [
    { code: '101', description: 'Road Credit' },
    { code: '102', description: 'Salvage Credit' },
  ],
  costTypes: [
    { code: 'CT1', description: 'Fixed' },
    { code: 'CT2', description: 'Variable' },
  ],
}

export const restHandlers = [
  http.get('http://localhost:3000/api/v1/users', () => {
    return new HttpResponse(JSON.stringify(users), {
      status: 200,
    })
  }),
  http.get('http://localhost:3000/api/v1/schedule1', () => HttpResponse.json(schedule1Doc)),
  http.get('http://localhost:3000/api/v1/schedule8/options', () =>
    HttpResponse.json(schedule8Options),
  ),
  // Default working-context handler: the ScheduleTombstone (and the global ContextBanner) fetch
  // GET /v1/mill-context on the current context, so schedule pages rendered in isolation would trip
  // MSW's onUnhandledRequest: 'error' without this. Echoes the requested millId/year so the tombstone's
  // stale-guard passes. Tests that assert specific banner content override this via server.use(...).
  http.get('http://localhost:3000/api/v1/mill-context', ({ request }) => {
    const params = new URL(request.url).searchParams
    const millId = Number(params.get('millId'))
    const reportYear = Number(params.get('year'))
    return HttpResponse.json({
      millId,
      millNumber: String(millId),
      millName: 'Test Mill',
      reportYear,
      schedules1To10Status: { code: 'D', description: 'Draft', date: '2017-01-01' },
      millViewable: true,
    })
  }),
]

// Exported so tests can register per-scenario handlers with server.use(...).
export const server = setupServer(...restHandlers)

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))

//  Close server after all tests
afterAll(() => server.close())

// Reset handlers after each test `important for test isolation`
afterEach(() => {
  server.resetHandlers()
})

// The viewport is global state like the MSW handlers, so it resets between tests. Reset in BEFORE-each
// rather than after: a `beforeAll(() => setLargeViewport(true))` block would otherwise silently expire
// after its first test. Listeners are NOT cleared blindly — React unmount is what should remove them,
// and wiping the Set here would destroy the evidence a leak regression leaves behind
// (see the unsubscribe assertion in LayoutSideNav.test.tsx).
beforeEach(() => {
  isLargeViewport = false
})
