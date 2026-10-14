package ca.bc.gov.nrs.ilcr.schedule8;

import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
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
 * Acceptance test — authorization on EDIT_SCHEDULE (AD-7) for the Schedule 8 page write path.
 * Security ON; drives the real {@code oauth2ResourceServer} chain + {@code @PreAuthorize}.
 * VIEW-only ({@code ILCR_SUBMITTER} without edit? here SUBMITTER holds EDIT) — an empty group is
 * denied (403); a submitter passes. Mirrors the Schedule 4 write-authz pattern.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("PUT/DELETE /api/v1/schedule8/pages — authorization on EDIT_SCHEDULE (AD-7)")
class Schedule8PageWriteAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule8/pages";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();
  private static final String VALID_BODY =
      """
      {"license": "LAUTH", "supportCentre": "SC1", "region": "R1", "becZone": "BZ1",
       "tsaNumber": "TSA5"}""";

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE (empty groups) -> PUT 403")
  void put_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "580")
                .param("year", "2021")
                .with(csrf())
                .with(jwtWithGroups(List.of()))
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE (empty groups) -> DELETE 403")
  void delete_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            delete(ENDPOINT + "/8810")
                .param("millId", "582")
                .param("year", "2021")
                .with(csrf())
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> PUT passes authz (not 403)")
  void put_submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "580")
                .param("year", "2021")
                .with(csrf())
                .with(canonicalSubmitter())
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> DELETE passes authz (idempotent no-op, not 403)")
  void delete_submitter_passesAuthorization() throws Exception {
    // Unknown page id in a Draft mill → idempotent no-op success; proves the submitter isn't
    // blocked.
    mockMvc
        .perform(
            delete(ENDPOINT + "/999999")
                .param("millId", "580")
                .param("year", "2021")
                .with(csrf())
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  // -----------------------------------------------------------------------------------------
  // The ADMIN row of the role×status matrix (Story 16.1; added on the #427 review). Mill 744/2021
  // is 1–10 'V' and silviculture 'D' (R__51) — so a gate that read the wrong track's column would
  // see Draft, refuse the administrator, and every test below would fail on a 409 instead of
  // passing vacuously. The shared unit truth table proves the component; these prove THIS
  // schedule's wiring to it, on the write verb AND on DELETE.
  // -----------------------------------------------------------------------------------------

  /** License 'LVER' is unique to mill 744, so the admin PUT adds its own page, not page 8990. */
  private static final String VERIFIED_BODY =
      """
      {"license": "LVER", "supportCentre": "SC1", "region": "R1", "becZone": "BZ1",
       "tsaNumber": "TSA5"}""";

  @Test
  @DisplayName("ILCR_ADMIN WRITES at a VERIFIED track -> 2xx, and the track stays 'V' (AD-9)")
  void admin_writesAtVerified() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "744")
                .param("year", "2021")
                .with(csrf())
                .with(jwtWithGroups(List.of("ILCR_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(VERIFIED_BODY))
        .andExpect(status().is2xxSuccessful())
        // The correction must not move the track, and the echo must report the status the gate
        // actually read — not a STATUS_DRAFT literal passed in its place.
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN DELETES a page at a VERIFIED track -> 2xx (the correction path)")
  void admin_deletesAtVerified() throws Exception {
    // Page 8990 is R__51's seeded delete target on this mill and carries no samples, so this
    // removes a real row rather than exercising the idempotent no-op arm the submitter probe above
    // uses. A DELETE still holding the pre-16.1 Draft-only literal answers 409 here while its
    // sibling PUT passes — and a refused-at-Draft probe cannot see that, because Draft-only and
    // the matrix agree an administrator may not write at 'D'.
    mockMvc
        .perform(
            delete(ENDPOINT + "/8990")
                .param("millId", "744")
                .param("year", "2021")
                .with(csrf())
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
                .param("millId", "744")
                .param("year", "2021")
                .with(csrf())
                .with(canonicalSubmitter())
                .contentType(MediaType.APPLICATION_JSON)
                .content(VERIFIED_BODY))
        .andExpect(status().isConflict());
  }
}
