package ca.bc.gov.nrs.ilcr.schedule8;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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
 * Acceptance test — authorization on EDIT_SCHEDULE (AD-7) for the Schedule 8 sample write path.
 * Security ON. Empty group → 403; {@code ILCR_SUBMITTER} passes. Mirrors the page-write authz
 * pattern.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("PUT/DELETE /api/v1/schedule8/pages/{pageId}/samples — authorization (AD-7)")
class Schedule8SampleWriteAuthorizationIT extends AbstractOracleIT {

  private static final String SAMPLES = "/api/v1/schedule8/pages/8910/samples";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();
  private static final String VALID_BODY =
      """
      {"contractId": "CAUTH", "groundBasePct": 100}""";

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE -> PUT sample 403")
  void put_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(SAMPLES)
                .param("millId", "591")
                .param("year", "2021")
                .with(csrf())
                .with(jwtWithGroups(List.of()))
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE -> DELETE sample 403")
  void delete_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            delete(SAMPLES + "/8911")
                .param("millId", "591")
                .param("year", "2021")
                .with(csrf())
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> PUT sample passes authz (not 403)")
  void put_submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            put(SAMPLES)
                .param("millId", "591")
                .param("year", "2021")
                .with(csrf())
                .with(canonicalSubmitter())
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> DELETE sample passes authz (idempotent no-op, not 403)")
  void delete_submitter_passesAuthorization() throws Exception {
    // Unknown sample id → idempotent no-op success; proves the submitter isn't blocked by
    // @PreAuthorize.
    mockMvc
        .perform(
            delete(SAMPLES + "/999999")
                .param("millId", "591")
                .param("year", "2021")
                .with(csrf())
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }
}
