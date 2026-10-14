# Modern FAM / CSS browser authentication

ILCR uses the same browser authentication pattern as LEXIS: `oidc-client-ts`, authorization
code with PKCE, a public client, tab-scoped `sessionStorage`, and signed CSS access tokens for
API requests. The backend checks issuer, signature, expiry, `azp`, `typ=Bearer`, supported
identity provider, and audit identity. ILCR also requires a valid directory GUID.

## GitHub Actions configuration

Create the `dev` GitHub Environment in this repository. The current deployment workflows bind
PR previews to `dev`, and merge deployments to `test`/`prod` where already enabled. Use the
existing OpenShift and database secrets; the auth migration requires **no new secret**.

Set these **Environment variables** in each of `dev`, `test`, and `prod`:

| Variable | Value |
| --- | --- |
| `ILCR_OIDC_ISSUER_URI` | The environment's issuer: `auth-server-url` + `realms/` + `realm`, with no trailing slash |
| `ILCR_OIDC_CLIENT_ID` | The environment's installation JSON `resource` |

Obtain both from the provisioned environment's CSS installation JSON. The dashboard request
number is **not** the client ID. Do not copy a confidential installation JSON or place a client
secret in frontend settings. See [CSS installation JSON documentation](https://bcgov.github.io/sso-docs/integrating-your-application/installation-json).

Optional variables, only when an override is needed:

- `ILCR_OIDC_IDIR_HINT`: defaults to `azureidir`.
- `ILCR_OIDC_BCEID_HINT`: defaults to `bceidbusiness`.
- `ILCR_OIDC_SITEMINDER_LOGOUT_URL`: defaults to `logontest7` outside PROD and `logon7` in PROD.

The init job validates issuer/client settings before applying templates. It writes public
auth configuration into ConfigMaps and mounts `/config.js` over the frontend placeholder.
Caddy reads the same environment-specific issuer for discovery/token/refresh requests.
The same image can therefore run in each environment without baking auth settings into it.

Draft PRs build images but skip preview deployment and deployed tests. Marking the PR ready
for review starts that workflow again and enables the DEV preview deployment.

Keep existing repository-level DEV deployment credentials while introducing the `dev`
Environment. TEST/PROD continue using their existing deployment/database secrets. If moving
credentials between scopes later, review all workflow callers before removing the originals.

## CSS and FAM setup

Use a separate public browser integration for this app, with IDIR MFA and Business BCeID.
Register root `/` for logout and `/authCallback` for login on each allowed origin:

- DEV: `https://nr-ilcr-0.apps.gold.devops.gov.bc.ca` through host `49`, plus `http://localhost:3000`.
- TEST: `https://nr-ilcr-test.apps.gold.devops.gov.bc.ca`.
- PROD: `https://ilcr.nrs.gov.bc.ca`, after route/certificate and CSS approval.

DEV previews use PR number modulo 50. The callback is computed from the current browser
origin, so localhost and each numbered preview return to their own app. Grant migration and
FAM application/role setup are operator steps; this branch performs none of them.

Require the access-token mappers for `identity_provider`, provider-specific username/GUID,
display name, email, and roles. Roles come from `client_roles`, falling back to
`resource_access.<configured client>.roles`. Provider hints select login only; they do not
grant application permissions.

Register `ILCR_ADMIN` and `ILCR_SUBMITTER` as the ILCR client role codes. IDIR/IDIR MFA
can hold the existing staff/admin or submitter capability; Business BCeID can only receive
submitter capability. Foreign roles, bare role names, prefixed aliases, and `FAM:` bookkeeping
roles grant no ILCR access. A valid identity without a role can read its own `/api/v1/me`
response and reaches the existing No Access screen.

Mill scope remains in the existing database associations. Preserve each person's directory
GUID from `idir_user_guid` or `bceid_user_guid`; never use Keycloak `sub` as the association
key. CSS GUIDs are canonicalized to uppercase hex, without hyphens, for the existing 32-character
directory key. Audit fields use `idir_username`/`bceid_username`, preserving the short audit
username rather than substituting a GUID. Check both mappings against existing records in DEV.
The active-association predicate and administrator bypass are unchanged.

## Session handling

API requests and user activity share one refresh operation. A rotating refresh token is spent
once, even with concurrent callers. Expired/revoked refresh tokens end the session; temporary
SSO/network failures preserve it and surface the failed request. The existing app idle limit
still applies. OAuth callbacks are shared across StrictMode/remounts and restore only a route
on this application's origin. Logout reads `id_token_hint` before removing local credentials,
then navigates through SiteMinder and the configured Keycloak realm back to the root URL.

## Local development

The tracked `frontend/public/config.js` opts into mock authentication on localhost only.
For real DEV sign-in, copy `frontend/public/config.example.js` to `config.js`, enter the DEV
issuer and client ID, and disable backend mock authentication. Use the same issuer/client in
the backend and frontend. Keep real database and directory-service credentials in ignored
`.env` files, never in public runtime config.

## Cutover and rollback

1. Provision CSS and complete the relevant provider approvals; configure the two variables.
2. Register the FAM application/role codes and migrate approved assignments to the right
   environment. Verify stable directory and audit identities against existing records.
3. Run credentialed DEV acceptance for IDIR MFA and Business BCeID: no role, permitted role,
   foreign role/client, logout, callback/deep-link restoration, renewal and denial cases.
4. Recheck TEST after deployment, including actual record/mill scope and audit writes. Local
   unit tests and synthetic fixtures do not establish deployed-role acceptance.
5. Authorize PROD only after its URL/certificate, role, provider, acceptance and rollback gates.

Rollback needs the previous application image **and its matching init/deployment templates**:
the runtime file/global and backend auth configuration changed. Retain the old Cognito
variables/secrets and grants until each environment passes its rollback window. Then remove
the obsolete auth-only settings listed below; database/OpenShift/NR User Lookup settings are
independent and must be retained.

## Retired auth settings

GitHub auth secrets: `USER_POOLS_ID`, `USER_POOLS_WEB_CLIENT_ID`.
GitHub auth variables: `COGNITO_DOMAIN`, `COGNITO_OAUTH_SCOPES`,
`COGNITO_REDIRECT_SIGN_IN`, `COGNITO_REDIRECT_SIGN_OUT` (and `COGNITO_REGION` if configured).
Do not remove `ILCR_USER_LOOKUP_*` settings: those belong to the independent ministry
directory lookup integration, not browser login. PROD deployment remains disabled in the
existing merge workflow.

## Local validation

Java 21 backend unit suites: 2502 tests passed. Frontend unit suites: 2605 tests
passed (Node 24), plus build and lint. OpenShift templates were rendered locally with synthetic
parameters, including the runtime issuer/client settings. These checks do not provision or
exercise CSS. Oracle container integration tests were not run because Docker is unavailable.

Repository TypeScript checks have pre-existing failures (CSP UI component types; ILCR's
project-reference configuration). Main/source comparison found no new error locations or
codes in this migration, and no errors in the changed production auth files.
