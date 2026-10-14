package ca.bc.gov.nrs.ilcr.schedule10;

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
 * Acceptance test for authorization on {@code VIEW_SCHEDULE} (AD-7) for Schedule 10. Security ON,
 * so this drives the real {@code oauth2ResourceServer} chain and {@code @PreAuthorize}.
 *
 * <p>Authorities derive through the production {@link FamJwtAuthenticationConverter} rather than
 * {@code jwt().authorities(...)} directly — Spring's test {@code jwt()} derives authorities from
 * the {@code scope} claim and would bypass the app's {@code cognito:groups} mapping entirely, so a
 * test written the easy way would pass without exercising production authorization at all.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/schedule10 — authorization on VIEW_SCHEDULE (AD-7)")
class Schedule10AuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule10";
  private static final String SEEDED_MILL = "710";
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
  @DisplayName("foreign group -> 403")
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
  @DisplayName("ILCR_SUBMITTER -> 200, and editable:true on a Draft track")
  void submitter_returns200AndEditable() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN -> 200")
  void admin_returns200() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("editable is server-authoritative — a non-Draft track is false for any caller")
  void nonDraftTrackEditabilityFollowsTheRole() throws Exception {
    // Mill 716 sits on track 'S'. Both production groups hold EDIT_SCHEDULE, so this proves the
    // flag follows the track status and not merely the caller's permissions (AD-9).
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", "716")
                .param("year", SEEDED_YEAR)
                .with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.editable", is(false)));

    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", "716")
                .param("year", SEEDED_YEAR)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isOk())
        // An administrator DOES edit at 'S' — the ministry correction path. Legacy granted it on
        // the same cell, and the shared editability component now implements the full matrix.
        .andExpect(jsonPath("$.editable", is(true)));
  }
}
