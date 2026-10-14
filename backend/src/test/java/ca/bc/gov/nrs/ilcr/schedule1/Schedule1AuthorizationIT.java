package ca.bc.gov.nrs.ilcr.schedule1;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test for authorization on VIEW_SCHEDULE (AD-7). Runs with security ON and drives the
 * real {@code oauth2ResourceServer} chain + {@code @PreAuthorize}. Authorities are derived through
 * the production {@link FamJwtAuthenticationConverter} (the spring-security-test {@code jwt()}
 * default reads only the {@code scope} claim, so we plug our converter into the {@code
 * .authorities(...)} overload) — so this exercises the real cognito:groups &rarr; role &rarr;
 * action path end to end.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/schedule1 — authorization on VIEW_SCHEDULE (AD-7)")
class Schedule1AuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule1";

  /** Since #359 check-status requires the on-screen body; its content is irrelevant to authz. */
  private static final String CHECK_BODY = "{\"lineItems\":[],\"otherCostsVolume\":null}";

  private static final long SEEDED_MILL = 514L;
  private static final int SEEDED_YEAR = 2021;
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  // With security on, oauth2ResourceServer().jwt() needs a JwtDecoder bean at config time. The
  // jwt() post-processor injects the Jwt directly (no real decoding), so a mock satisfies
  // construction. Real FAM decoder wiring (issuer/jwk) is the deferred auth story.
  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no VIEW_SCHEDULE (empty cognito:groups) -> 403")
  void noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", String.valueOf(SEEDED_MILL))
                .param("year", String.valueOf(SEEDED_YEAR))
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("foreign group (no ILCR_ suffix) -> 403")
  void foreignGroup_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", String.valueOf(SEEDED_MILL))
                .param("year", String.valueOf(SEEDED_YEAR))
                .with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER group -> passes authz (not 403)")
  void submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", String.valueOf(SEEDED_MILL))
                .param("year", String.valueOf(SEEDED_YEAR))
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("ILCR_ADMIN group -> passes authz (not 403)")
  void admin_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", String.valueOf(SEEDED_MILL))
                .param("year", String.valueOf(SEEDED_YEAR))
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("check-status is VIEW-gated: no VIEW_SCHEDULE -> 403 (Story 2.6)")
  void checkStatus_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT + "/check-status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(CHECK_BODY)
                .param("millId", String.valueOf(SEEDED_MILL))
                .param("year", String.valueOf(SEEDED_YEAR))
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  /**
   * The case above is also refused by Story 5.7 mill-scope (no associated GUID), which raises the
   * same 403 body — so on its own it would stay green without the VIEW_SCHEDULE gate. This caller
   * carries the canonical submitter's GUID, which passes mill-scope for the seeded mill, but no
   * ILCR group: only the {@code @PreAuthorize} gate can refuse it.
   */
  @Test
  @DisplayName("check-status: mill-associated GUID but no ILCR group -> 403 from the gate itself")
  void checkStatus_millAssociatedWithoutGroup_returns403() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT + "/check-status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(CHECK_BODY)
                .param("millId", String.valueOf(SEEDED_MILL))
                .param("year", String.valueOf(SEEDED_YEAR))
                .with(
                    jwt()
                        .jwt(
                            j ->
                                j.claim("idir_user_guid", CANONICAL_SUBMITTER_GUID)
                                    .claim("identity_provider", "azureidir")
                                    .claim("client_roles", List.of()))
                        .authorities(j -> CONVERTER.convert(j).getAuthorities())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("check-status: ILCR_SUBMITTER group -> passes authz (2xx)")
  void checkStatus_submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT + "/check-status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(CHECK_BODY)
                .param("millId", String.valueOf(SEEDED_MILL))
                .param("year", String.valueOf(SEEDED_YEAR))
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }
}
