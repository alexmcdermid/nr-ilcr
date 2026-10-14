package ca.bc.gov.nrs.ilcr.schedule6;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test for authorization on VIEW_SCHEDULE (AD-7) for Schedule 6. Security ON; drives the
 * real {@code oauth2ResourceServer} chain + {@code @PreAuthorize}. Authorities derive through the
 * production {@link FamJwtAuthenticationConverter}, mirroring the Schedule 1/2/4 pattern.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/schedule6 — authorization on VIEW_SCHEDULE (AD-7)")
class Schedule6AuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule6";
  private static final String SEEDED_MILL = "514";
  private static final String SEEDED_YEAR = "2021";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

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
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
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
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
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
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("ILCR_ADMIN group -> passes authz (not 403)")
  void admin_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful());
  }

  // Task 3: DELETE requires EDIT_SCHEDULE, not VIEW_SCHEDULE (AD-7) -- a VIEW-only caller must be
  // rejected the same as the writes, never merely by naming the read permission above.
  @Test
  @DisplayName("DELETE /records/{id} with no group -> 403")
  void deleteRoadRecord_noGroup_returns403() throws Exception {
    mockMvc
        .perform(
            delete("/api/v1/schedule6/records/8358")
                .with(csrf())
                .param("millId", "666")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }
}
