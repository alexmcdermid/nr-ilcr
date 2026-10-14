package ca.bc.gov.nrs.ilcr.schedule2;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
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
 * Authorization on VIEW_SCHEDULE (AD-7) for POST check-status. Security ON; drives the real {@code
 * oauth2ResourceServer} chain + {@code @PreAuthorize}. A principal without VIEW_SCHEDULE must get
 * 403 {@code problem+json}; a submitter/admin passes authz. Mirrors {@link
 * Schedule2AuthorizationIT}.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("POST /api/v1/schedule2/check-status — authorization on VIEW_SCHEDULE (AD-7)")
class Schedule2CheckStatusAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule2/check-status";

  /** Since #359 the endpoint requires the on-screen body; its content is irrelevant to authz. */
  private static final String BODY = "{\"purchasedLogCostCost\":null}";

  private static final long SEEDED_MILL = 514L;
  private static final int SEEDED_YEAR = 2021;
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no VIEW_SCHEDULE (empty cognito:groups) -> 403 problem+json")
  void noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
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
  @DisplayName("mill-associated GUID but no ILCR group -> 403 from the VIEW_SCHEDULE gate itself")
  void millAssociatedWithoutGroup_returns403() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
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
  @DisplayName("ILCR_SUBMITTER group -> passes authz (not 403)")
  void submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
                .param("millId", String.valueOf(SEEDED_MILL))
                .param("year", String.valueOf(SEEDED_YEAR))
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }
}
