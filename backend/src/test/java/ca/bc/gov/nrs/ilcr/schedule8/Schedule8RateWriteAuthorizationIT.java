package ca.bc.gov.nrs.ilcr.schedule8;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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
 * Acceptance test — authorization on EDIT_SCHEDULE (AD-7) for the Schedule 8 rate-detail write
 * path. Security ON. Empty group → 403; {@code ILCR_SUBMITTER} passes. Mirrors the page/sample
 * write patterns.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("POST/DELETE /api/v1/schedule8/samples/{sampleId}/rates — authorization (AD-7)")
class Schedule8RateWriteAuthorizationIT extends AbstractOracleIT {

  // Targets mill 595 / sample 8951 — the submitter POST persists a harmless extra rate row there
  // that
  // no other IT counts (Schedule8RateWriteIT asserts specific rate ids under 594/8941 and
  // 595/8953).
  private static final String RATES = "/api/v1/schedule8/samples/8951/rates";
  private static final int MILL = 595;
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();
  private static final String VALID_BODY =
      """
      {"costItemCode": 82, "costingRate": 5.00, "costTypeCode": "CT1"}""";

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE -> POST rate 403")
  void post_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            post(RATES)
                .param("millId", String.valueOf(MILL))
                .param("year", "2021")
                .with(csrf())
                .with(jwtWithGroups(List.of()))
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE -> DELETE rate 403")
  void delete_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            delete(RATES + "/8952")
                .param("millId", String.valueOf(MILL))
                .param("year", "2021")
                .with(csrf())
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> POST rate passes authz (not 403)")
  void post_submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            post(RATES)
                .param("millId", String.valueOf(MILL))
                .param("year", "2021")
                .with(csrf())
                .with(canonicalSubmitter())
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE -> PUT rate 403")
  void put_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(RATES + "/8952")
                .param("millId", String.valueOf(MILL))
                .param("year", "2021")
                .with(csrf())
                .with(jwtWithGroups(List.of()))
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> PUT rate passes authz (404 unknown row, not 403)")
  void put_submitter_passesAuthorization() throws Exception {
    // Authz passes → the handler runs → 404 for the unknown row id (a 403 would mean denied).
    mockMvc
        .perform(
            put(RATES + "/999999")
                .param("millId", String.valueOf(MILL))
                .param("year", "2021")
                .with(csrf())
                .with(canonicalSubmitter())
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isNotFound());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> DELETE rate passes authz (idempotent no-op, not 403)")
  void delete_submitter_passesAuthorization() throws Exception {
    // Unknown row id → idempotent no-op success; proves the submitter is not blocked by
    // @PreAuthorize.
    mockMvc
        .perform(
            delete(RATES + "/999999")
                .param("millId", String.valueOf(MILL))
                .param("year", "2021")
                .with(csrf())
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }
}
