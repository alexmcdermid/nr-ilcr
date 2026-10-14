package ca.bc.gov.nrs.ilcr.schedule1;

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
 * RED-PHASE ATDD SCAFFOLD — Story 2.1 (AD-7). Authorization on EDIT_SCHEDULE for the write verbs.
 *
 * <p>Runs with security ON and drives the real {@code oauth2ResourceServer} chain +
 * {@code @PreAuthorize} — authorities are derived through the production {@link
 * FamJwtAuthenticationConverter} (same pattern as {@link Schedule1AuthorizationIT}, which covers
 * VIEW_SCHEDULE on GET). A principal without EDIT_SCHEDULE must get 403 {@code problem+json} on
 * both PUT and DELETE, with no data change.
 *
 * <p>RED before implementation: with no PUT/DELETE handler mapped, security returns 405, not the
 * asserted 403. Class-level {@code @Disabled} is the red-phase gate; dev-story removes it once the
 * write endpoints carry {@code @PreAuthorize("@permissions.hasPermission(authentication,
 * 'EDIT_SCHEDULE')")}.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("PUT/DELETE /api/v1/schedule1 — authorization on EDIT_SCHEDULE (AD-7)")
class Schedule1WriteAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule1";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  // With security on, oauth2ResourceServer().jwt() needs a JwtDecoder bean at config time; the
  // jwt() post-processor injects the Jwt directly, so a mock satisfies construction.
  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private static final String BODY =
      """
        { "revisionCount": 0,
          "lineItems": [ { "costItemCode": 12, "volume": 1000, "cost": 5000 } ],
          "silviculture": { "actualSpent": { "volume": 1, "cost": 1 }, "accruedLessActual": { "volume": null, "cost": null } },
          "otherCostsVolume": 0 }
        """;

  @Test
  @DisplayName("no EDIT_SCHEDULE (empty cognito:groups) -> PUT 403 problem+json")
  void put_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "518")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE (empty cognito:groups) -> DELETE 403 problem+json")
  void delete_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            delete(ENDPOINT)
                .param("millId", "519")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER holds EDIT_SCHEDULE -> PUT passes authz (not 403)")
  void put_submitter_passesAuthorization() throws Exception {
    // Dedicated mill 521 (REVISION_COUNT 0, only this test writes it) so the hard-coded token in
    // BODY can never be made stale by another class sharing the container.
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "521")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  // -----------------------------------------------------------------------------------------
  // The ADMIN row of the role×status matrix (Story 16.1; added on the #427 review). Mill 737/2021
  // is 1–10 'V' and silviculture 'D' (R__51) — so a gate that read the wrong track's column would
  // see Draft, refuse the administrator, and every test below would fail on a 409 instead of
  // passing vacuously. The shared unit truth table proves the component; these prove THIS
  // schedule's wiring to it, on both write verbs.
  // -----------------------------------------------------------------------------------------

  @Test
  @DisplayName("ILCR_ADMIN WRITES at a VERIFIED track -> 2xx, and the track stays 'V' (AD-9)")
  void admin_writesAtVerified() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "737")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        // The correction must not move the track, and the echo must report the status the gate
        // actually read — not a STATUS_DRAFT literal passed in its place.
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN DELETES at a VERIFIED track -> 2xx (the correction path)")
  void admin_deletesAtVerified() throws Exception {
    // Summary 1280 is R__51's seeded delete target on this mill, so this removes a real row rather
    // than exercising the idempotent nothing-deleted arm — and it needs no PUT of its own, which
    // would collide on REVISION_COUNT with the sibling write test. A DELETE still holding the
    // pre-16.1 Draft-only literal answers 409 here while its sibling PUT passes: the divergence a
    // refused-at-Draft probe cannot see, because Draft-only and the matrix agree that an
    // administrator may not write at 'D'.
    mockMvc
        .perform(
            delete(ENDPOINT)
                .param("millId", "737")
                .param("year", "2021")
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("A SUBMITTER at that same VERIFIED track -> 409: only the ministry corrects")
  void submitter_refusedAtVerified() throws Exception {
    // The other half of the row. Without it, admin_writesAtVerified alone would also pass if the
    // gate had simply been widened to "anyone may edit at V".
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "737")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }
}
