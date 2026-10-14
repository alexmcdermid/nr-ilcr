# ILCR — Interior Logging Costs Reporting

ILCR collects annual logging cost information from forestry licensees to support interior stumpage rate setting in British Columbia. This repository is the modernized ILCR application, which replaces the legacy ILCR 2.0.4 (Java 8 / JSF / WebADE).

- **Licensees** (`ILCR_SUBMITTER`) enter Schedules 1–11 for their mills and submit them.
- **Ministry staff** (`ILCR_ADMIN`) review, correct, verify and reverse reports, and administer mills, users,
  reporting years, Home content and code tables.
- **Both roles** print schedules and run the Mill Information and Mill Status reports; submitters see only their
  own mills. The data extract is for Ministry staff only.

The application keeps the existing Oracle `THE` database as its unchanged system of record and signs users in through modern FAM / BC Gov CSS.

## Stack

- Frontend: React 19, TypeScript, Vite, TanStack Router, IBM Carbon with the BC Gov NR theme, oidc-client-ts (FAM/CSS)
- Backend: Java 21, Spring Boot 4.1.1, Maven, executable JVM JAR, Spring Security OAuth2 resource server, Spring Data JDBC + Hikari against Oracle `THE`, embedded JasperReports 7
- Tests: JUnit + Testcontainers Oracle (backend), Vitest + Testing Library + MSW (frontend), Playwright + playwright-bdd + axe (`frontend/e2e`)
- Local platform: direct Maven/npm runs or Docker Compose with backend, frontend, optional Caddy, and sanitized Oracle env wiring
- Target platform: OpenShift Gold using the `backend`, `frontend` and `database` deployment packages

## Project Layout

```text
backend/     Spring Boot API (one package per schedule and feature)
frontend/    React/Vite web app; frontend/e2e is the Playwright + playwright-bdd suite
database/    Oracle Free image for the CI e2e database (tools namespace)
common/      OpenShift init template, API smoke test, k6 load tests
scripts/     Local DDL helper and read-only delivery-schema probes
docs/        API inventory, decision records and delivery-schema probe output
monitoring/  Sysdig alert templates (used by the PROD monitor job)
```

## Local Development

Prerequisites:

- JDK 21
- Maven 3.9+
- Node 24+
- Docker or Podman for the full local stack
- Optional Oracle dev DB credentials in a local, ignored `.env`

Run the Spring Boot backend directly:

```powershell
cd backend
$env:SPRING_PROFILES_ACTIVE = "local"
mvn spring-boot:run
```

The backend listens on `http://localhost:8080` by default.

- Health: `GET /api/health`
- Schedule 1 API: `GET /api/v1/schedule1`

Run the frontend directly against the local backend:

```powershell
cd frontend
npm ci
$env:BACKEND_URL = "http://localhost:8080"
npm run dev
```

The frontend shell includes the NRS Carbon layout, light/dark theme toggle, side navigation, and (on localhost) a top-right mock user selector. The mock personas are:

- Alex Admin: `ILCR_ADMIN`
- Sam Submitter: `ILCR_SUBMITTER`

Run the full local stack:

```powershell
copy .env.example .env
docker compose up --build backend frontend
```

The frontend is available at `http://localhost:3000`. In compose, the backend is mapped to `http://localhost:8080` and runs inside the container on port `8080`.

Locally the backend starts with security off (mock principal from the `X-Mock-Groups` header) and no datasource: both `ILCR_SECURITY_ENABLED` and `ILCR_DATASOURCE_ENABLED` default to `false` in `application.yml`. Deployed pods always run with security on (see [OpenShift Status](#openshift-status)).

To connect Oracle on backend startup, put local values in ignored `.env` and set `ILCR_DATASOURCE_ENABLED=true` for Docker Compose:

```powershell
SPRING_DATASOURCE_URL=jdbc:oracle:thin:@//<host>:1521/<service-name>
SPRING_DATASOURCE_USERNAME=<username>
SPRING_DATASOURCE_PASSWORD=<password>
ILCR_DATASOURCE_ENABLED=true
```

For direct Maven runs, the `oracle` Spring profile also enables the datasource:

```powershell
cd backend
$env:SPRING_PROFILES_ACTIVE = "local,oracle"
mvn spring-boot:run
```

Do not commit real database passwords. Put local values in `.env`; the file is git-ignored.

### Corporate SSL/TLS Intercept & Certificate Issues (e.g., Zscaler / PKIX) — Local Workaround

*Note: This is a specific workaround for developers behind a corporate SSL-decryption/packet-inspection gateway (such as Zscaler) and is **not** required for all developers (e.g., if you are on a direct internet connection).*

If your corporate network performs SSL decryption/packet-inspection, Maven inside the isolated Docker container may fail to connect to Maven Central (all dependencies, including JasperReports 7, resolve from Central — the build declares no custom `<repositories>`) with a `PKIX path building failed` error.

The recommended, zero-import workaround is to leverage your Windows host's trusted certificate store by caching the dependencies on Windows once, and mounting your host's `.m2` repository into the container:

1. **Seed the cache on Windows**:
   Run this once inside your Windows terminal to download and cache the libraries (which automatically trusts your corporate certificate):
   ```powershell
   cd backend
   mvn clean install -DskipTests
   ```
2. **Mount the cache in your local environment**:
   Set the `M2_HOME` variable inside your local, ignored `.env` file pointing to your host's `.m2` directory:
   ```properties
   M2_HOME=/mnt/c/Users/<your-username>/.m2
   ```
   Docker Compose will automatically detect this variable and mount your local Windows Maven cache into the container's `/root/.m2` path, bypassing the certificate handshake issues completely!

### Authentication (modern FAM / CSS)

The SPA uses a public OIDC client with PKCE and signed CSS access tokens. Runtime configuration
comes from `frontend/public/config.js`, replaced by a ConfigMap in deployed environments.
Local mock mode is enabled only with `mockUser: true` on localhost and backend security off.

For real login, configure the environment's `ILCR_OIDC_ISSUER_URI` and `ILCR_OIDC_CLIENT_ID`,
set frontend `mockUser: false`, and enable backend security with the `openshift` profile's
SSO configuration. See [the migration/setup guide](docs/fam-keycloak-migration.md) for exact
variables, callbacks, identity/mill mapping, acceptance and rollback steps.

## Frontend Shared Conventions

Reusable building blocks and global styles that new schedule/feature pages should adopt rather than
re-implement (paths under `frontend/src`):

- **Schedule tombstone header** — `components/core/ScheduleTombstone`. A two-column page header: left
  is the page identity (`title` + a `subtitle` sub-page label), right is the working-context
  mill/status lines. It replaces the old `PageTitle` header on schedule pages and owns the
  `document.title` side effect. `subtitle` accepts a string or a `string[]` rendered breadcrumb-style,
  so deeper sub-pages can thread their level (e.g. `["Report Tree to Truck Costs", "License", "Sample"]`).
- **Working context** — `components/core/WorkingContext`. `useWorkingContext(millId, year)` fetches
  `GET /v1/mill-context` with the stale-response guards; `WorkingContextLines` renders the three legacy
  lines (`Mill: … - Year: …`, `Sch 1-10 …`, `Sch 11 …`). Both the tombstone and any future banner reuse
  these. The former global `ContextBanner` was removed from `Layout` — mill/status now renders once, in
  the tombstone header.
- **Currency formatting** — `fmtCurrency` in `utils/number.ts`. Thousands-separated with two decimals
  (`1234.5 → "1,234.50"`, `null → "—"`), no `$` sign (the column header carries the unit). Use it for
  `$/m³`/rate and other currency read-only cells; keep `fmt` for plain integer/quantity cells.
- **Footer** — `components/Layout/Footer`, rendered once by `Layout` on every route. Shows the app
  version (left) and the BC Gov copyright/disclaimer/privacy/accessibility links (centred). The version
  comes from `__APP_VERSION__`, inlined from `package.json` by a Vite `define` (see `vite.config.ts`;
  typed in `src/vite-env.d.ts`) — reuse that global for any other build-time constant.
- **Global styles** (`styles/_overrides.scss`, `styles/_custom.scss`) — buttons and fields share one
  48px (3rem) height app-wide, across size variants, via the `--cds-layout-size-height-local` token
  (Story 30.2), so controls take no `size` prop; Carbon's Dropdown ignores the token and is pinned
  separately. Text areas share the same light-grey field background (`#f4f4f4`) as the text inputs.
  The height contract is pinned by `styles/__tests__/controlHeightContract.test.ts`.

## Git Ignore Policy

The repository tracks source, deploy templates, and safe examples such as `.env.example`. It ignores local secrets, certificates, build outputs, dependency folders, coverage reports, Playwright reports, Maven `target/`, and Vite `dist/`.

If a local setting is needed by the team, add a sanitized example to `.env.example` or this README instead of committing a developer-specific `.env`.

## Backend Notes

The backend follows the CSP-style JVM deployment path: Spring Boot 4, executable JAR, Log4j2 logging, actuator health, Maven verification, and CycloneDX SBOM generation. Graal/native-image support is intentionally not part of this build.

- **Package shape.** Each feature package (`schedule1` … `schedule11`, `checkstatus`, `reporting`, `dataextract`, `millmaintenance`, `assignment`, …) has:
  - a controller that implements an `api/*Api` interface holding the request mappings;
  - `dto/` records;
  - a service that owns the transactions;
  - a Spring Data JDBC repository with explicit `@Query` SQL against `THE`.
- **No schema changes.** The application runs no DDL: Flyway is test-scope only and builds the throwaway test databases.
- **Authorization is server-side.**
  - Every endpoint requires authentication. Every data endpoint also checks a permission action with
    `@PreAuthorize`; the exceptions are the identity and working-context reads (`/me`, `/mills`,
    `/reporting-years`, `/mill-context`, `/home-content/mine`).
  - Schedule writes also pass the role × status editability matrix.
  - Submitters are limited to mills they are actively assigned to.
- **Errors** are RFC 7807 `ProblemDetail`, and message text comes from `messages.properties` under the legacy keys.

Every endpoint and the permission it requires is listed in [`docs/api-inventory.md`](docs/api-inventory.md). Keep it in step when you add or change an endpoint.

## OpenShift Status

- **Environments.** Pull requests that touch deployable paths deploy a sandbox (zone = PR number mod 50). Merges to `main` deploy to TEST.
- **PROD is not yet enabled.** The PROD pipeline (deploy, Sysdig monitor, image promotion) is commented out in `.github/workflows/merge.yml` until the `prod` GitHub environment has its own `ORACLEDB_*` secrets. Restore those jobs to open PROD.
- **Security is always on.** Deployed pods always enforce FAM/CSS access-token authentication: `ILCR_SECURITY_ENABLED` is hard-coded `"true"` in `backend/openshift.deploy.yml`.
- **Datasource.** `ILCR_DATASOURCE_ENABLED` defaults to `true`. It can be set to `false` with a **repository-level** GitHub variable for a data-less smoke deployment. The deploy matrix reads it before the environment attaches, so an environment-scoped value is ignored.
- **Fail-closed guard.** The backend also refuses to start a deployed pod with security off while the datasource is on (`DeployedSecurityGuard`), so mock auth can never serve real data.

The NR User Lookup directory search (`ILCR_USER_LOOKUP_ENABLED`, DL-27) is a separate switch and ships `false` in every environment. Only its non-secret half is wired in `backend/openshift.deploy.yml` — the service-account credential (`ILCR_USER_LOOKUP_CLIENT_ID` / `_SECRET`) is a per-environment Vault secret that does not exist yet, and a `secretKeyRef` to a missing Secret would fail the pod, so it lands with the DL-27 onboarding work. The backend refuses to start with the flag on and any of the four values blank, so the switch and the credential cannot drift apart. While the flag is off the endpoint is not routed at all and `GET /api/v1/users/lookup` answers 404.

## Verification

Backend:

```powershell
cd backend
mvn verify                      # unit tests, JaCoCo, Checkstyle, Spotless — integration tests are SKIPPED
mvn verify -P integration-test  # integration tests only (Testcontainers Oracle; needs Docker)
mvn verify -P all-tests         # both
```

`mvn verify` on its own prints BUILD SUCCESS without running any `*IT`; check the `Tests run:` count before reading a green build as integration coverage. Run `mvn spotless:apply` first — `spotless:check` fails the build.

Frontend:

```powershell
cd frontend
npm ci
npm run lint
npm run test:cov
npm run build
```

End-to-end tests live in the self-contained `frontend/e2e` package, so they have their own
`node_modules` and are not installed by the `frontend` `npm ci` above. Install them once, then run:

```powershell
cd frontend/e2e
npm ci
npm test          # equivalently, from frontend/: npm run test:e2e
```

`npm run test:e2e` (which shells out to the `e2e` package) requires the full running stack —
frontend `:3000`, backend `:8080`, and the seeded Oracle DB — plus a browser channel. See
[`frontend/e2e/README.md`](frontend/e2e/README.md) for the bring-up. Playwright runs against the local
Vite app by default; set `E2E_BASE_URL` only when intentionally testing a deployed route.
