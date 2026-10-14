package ca.bc.gov.nrs.ilcr.reporting;

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
 * Acceptance test for authorization on VIEW_SCHEDULE (AD-7) for the combined Print Schedules
 * endpoint. Security ON; drives the real {@code oauth2ResourceServer} chain +
 * {@code @PreAuthorize}. Print is read-only for every role (BR-01), so VIEW_SCHEDULE is the gate.
 * Authorities derive through the PRODUCTION {@link FamJwtAuthenticationConverter} (mirrors {@link
 * ReportAuthorizationIT}).
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("POST /api/v1/reports/print — authorization on VIEW_SCHEDULE (AD-7)")
class PrintAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/reports/print";
  private static final String SEEDED_MILL = "514";
  private static final String SEEDED_YEAR = "2021";
  private static final String SELECTION =
      """
      {"schedule9":true,"printScheduleInformation":true,"printComments":true}
      """;
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no token (anonymous) -> 401, the authentication boundary")
  void anonymous_returns401() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT)
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(SELECTION)
                .accept(MediaType.APPLICATION_PDF))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("no VIEW_SCHEDULE (empty cognito:groups) -> 403")
  void noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT)
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(SELECTION)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("foreign group (no ILCR_ prefix) -> 403")
  void foreignGroup_returns403() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT)
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(SELECTION)
                .with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER group -> passes authz, streams the PDF")
  void submitter_passesAuthorization() throws Exception {
    streamPdf(
            post(ENDPOINT)
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(SELECTION)
                .accept(MediaType.APPLICATION_PDF)
                .with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_PDF));
  }

  @Test
  @DisplayName("ILCR_ADMIN group -> passes authz, streams the PDF")
  void admin_passesAuthorization() throws Exception {
    streamPdf(
            post(ENDPOINT)
                .param("millId", SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(SELECTION)
                .accept(MediaType.APPLICATION_PDF)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_PDF));
  }
}
