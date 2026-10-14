package ca.bc.gov.nrs.ilcr.checkstatus;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test — authorization on {@code VIEW_SCHEDULE} plus mill scope for the sweep (Story
 * 15.1 AC 7; AD-7, FR2). Security ON. No group → 403; the canonical associated submitter and an
 * admin both reach a 200; a submitter NOT associated to the mill is 403'd by the shared guard's
 * mill-scope check — the case the epic's "any signed-in user" phrasing would have let through.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/check-status — authorization on VIEW_SCHEDULE + mill scope (Story 15.1)")
class CheckStatusAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/check-status";
  private static final String MILL = "514";
  private static final String YEAR = "2021";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  /** A submitter with NO xref association to any mill (32-char GUID, never seeded). */
  private RequestPostProcessor unassociatedSubmitter() {
    return jwt()
        .jwt(
            j ->
                j.claim("idir_user_guid", "UNASSOCIATEDSUBMITTERXXXX0000001")
                    .claim("identity_provider", "azureidir")
                    .claim("client_roles", List.of("ILCR_SUBMITTER")))
        .authorities(new SimpleGrantedAuthority("SUBMITTER"));
  }

  private RequestPostProcessor admin() {
    return jwtWithGroups(List.of("ILCR_ADMIN"));
  }

  @Test
  @DisplayName("no VIEW_SCHEDULE -> 403 problem+json")
  void noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT).param("millId", MILL).param("year", YEAR).with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("canonical associated ILCR_SUBMITTER -> 200 with all twelve")
  void associatedSubmitter_returns200() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).param("millId", MILL).param("year", YEAR).with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.schedules1To10.schedules.length()").value(11))
        .andExpect(jsonPath("$.schedule11.schedules.length()").value(1));
  }

  @Test
  @DisplayName("ILCR_ADMIN (tied to no mill) -> 200")
  void admin_returns200() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).param("millId", MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName(
      "submitter NOT associated to the mill -> 403 (mill scope, not the epic's 'any user')")
  void unassociatedSubmitter_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT).param("millId", MILL).param("year", YEAR).with(unassociatedSubmitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }
}
