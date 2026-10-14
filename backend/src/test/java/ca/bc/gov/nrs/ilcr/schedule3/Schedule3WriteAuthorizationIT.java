package ca.bc.gov.nrs.ilcr.schedule3;

import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
 * Acceptance test for authorization on EDIT_SCHEDULE for the Schedule 3 writes (AD-7). Security ON;
 * a caller with no ILCR group is denied 403 on PUT and DELETE (before any persistence). The write
 * behavior itself is proven security-off by {@link Schedule3WriteIT}.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("PUT/DELETE /api/v1/schedule3 — authorization on EDIT_SCHEDULE (AD-7)")
class Schedule3WriteAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule3";
  private static final String BODY =
      """
      { "revisionCount": 0, "overrideHarvestTotalPop": "N", "lineItems": [],
        "popTimberVolume": 5000, "crownTimberVolume": 5000 }
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
  @DisplayName("PUT without permission → 403")
  void putNoPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "573")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("DELETE without permission → 403")
  void deleteNoPermission_returns403() throws Exception {
    mockMvc
        .perform(
            delete(ENDPOINT)
                .param("millId", "573")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  // -----------------------------------------------------------------------------------------
  // The ADMIN row of the role×status matrix (Story 16.1; added on the #427 review). Mill 739/2021
  // is 1–10 'V' and silviculture 'D' (R__51) — so a gate that read the wrong track's column would
  // see Draft, refuse the administrator, and every test below would fail on a 409 instead of
  // passing vacuously. The shared unit truth table proves the component; these prove THIS
  // schedule's wiring to it, on the write verb AND on DELETE.
  // -----------------------------------------------------------------------------------------

  @Test
  @DisplayName("ILCR_ADMIN WRITES at a VERIFIED track -> 2xx, and the track stays 'V' (AD-9)")
  void admin_writesAtVerified() throws Exception {
    // Mill 739 carries no Schedule 1 summary, so this also exercises the BR-09 Crown Timber push
    // creating what it needs on an admin correction rather than on a licensee's first save.
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "739")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN DELETES at a VERIFIED track -> 2xx (the correction path)")
  void admin_deletesAtVerified() throws Exception {
    // Summary 1282 is R__51's seeded delete target on this mill, so this removes a real row rather
    // than exercising the idempotent nothing-deleted arm — and it needs no PUT of its own, which
    // would collide on REVISION_COUNT with the sibling write test. A DELETE still holding the
    // pre-16.1 Draft-only literal answers 409 here while its sibling PUT passes: the divergence a
    // refused-at-Draft probe cannot see, because Draft-only and the matrix agree that an
    // administrator may not write at 'D'.
    mockMvc
        .perform(
            delete(ENDPOINT)
                .param("millId", "739")
                .param("year", "2021")
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("A SUBMITTER at that same VERIFIED track -> 409: only the ministry corrects")
  void submitter_refusedAtVerified() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "739")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }
}
