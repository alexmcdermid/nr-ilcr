package ca.bc.gov.nrs.ilcr.schedule5;

import static org.hamcrest.Matchers.is;
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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test for authorization on VIEW_SCHEDULE (AD-7) for Schedule 5. Security ON; drives the
 * real {@code oauth2ResourceServer} chain + {@code @PreAuthorize}.
 *
 * <p>Authorities derive through the PRODUCTION {@link FamJwtAuthenticationConverter} rather than
 * {@code spring-security-test}'s default, which builds authorities from the {@code scope} claim and
 * would bypass the app's own group mapping entirely — the test would then pass without ever
 * exercising the real rule. Mirrors the Schedule 1/2/4/6 pattern.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/schedule5 — authorization on VIEW_SCHEDULE (AD-7)")
class Schedule5AuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule5";
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
  @DisplayName("foreign group (no ILCR_ prefix) -> 403")
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
  @DisplayName("ILCR_SUBMITTER group -> passes authz and gets editable:true on the Draft context")
  void submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful())
        // Asserting the flag, not just the status, is what proves the controller's EDIT_SCHEDULE
        // lookup reaches the response through the real security chain. It cannot prove the FALSE
        // branch — both shipped roles hold EDIT_SCHEDULE, so no JWT can produce a view-only
        // caller; Schedule5ControllerTest mocks the collaborator to cover that half.
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN group -> passes authz but is READ-ONLY on a Draft context (AD-9)")
  void admin_passesAuthorizationButIsReadOnlyAtDraft() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        // Administrator is not a superset of submitter: the statuses are a hand-off chain, so while
        // the track is Draft the mill owns it and the ministry reads only.
        .andExpect(jsonPath("$.editable", is(false)));
  }
}
