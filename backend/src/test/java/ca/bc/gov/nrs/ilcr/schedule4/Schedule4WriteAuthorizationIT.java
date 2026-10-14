package ca.bc.gov.nrs.ilcr.schedule4;

import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
 * Authorization on EDIT_SCHEDULE (AD-7) for the Schedule 4 location write verbs. Security ON;
 * drives the real {@code oauth2ResourceServer} chain + {@code @PreAuthorize}. A principal without
 * EDIT_SCHEDULE must get 403 {@code problem+json} on both PUT and DELETE; a submitter passes authz.
 * Mirrors {@link ca.bc.gov.nrs.ilcr.schedule2.Schedule2WriteAuthorizationIT}. Uses the dedicated V8
 * mill 543 ("Authz Dump", primary id 8020, revision 0) so the hard-coded token can never be made
 * stale by another class sharing the container.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("PUT/DELETE /api/v1/schedule4/locations — authorization on EDIT_SCHEDULE (AD-7)")
class Schedule4WriteAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule4/locations";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private static final String BODY =
      """
      { "id": 8020, "revisionCount": 0, "name": "Authz Dump",
        "categories": [ { "code": 40, "volume": 100, "cost": 5000, "distance": null } ] }
      """;

  @Test
  @DisplayName("no EDIT_SCHEDULE (empty cognito:groups) -> PUT 403 problem+json")
  void put_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "543")
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
                .param("millId", "543")
                .param("year", "2021")
                .param("id", "8020")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER holds EDIT_SCHEDULE -> PUT passes authz (not 403)")
  void put_submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "543")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  // ---- Sub-page row write verbs (Story 4.3) share the EDIT_SCHEDULE gate.
  // -------------------------

  private static final String ROWS = "/api/v1/schedule4/locations/8020/rows";
  private static final String ROW_BODY =
      """
      { "type": "TOWING", "description": "Authz row", "distance": 10.0, "volume": 50, "cost": 2000,
        "cycle": null }
      """;

  @Test
  @DisplayName("no EDIT_SCHEDULE -> POST row 403 problem+json")
  void postRow_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            post(ROWS)
                .param("millId", "543")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(ROW_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE -> DELETE row 403 problem+json")
  void deleteRow_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            delete("/api/v1/schedule4/locations/8020/rows/999999")
                .param("millId", "543")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER holds EDIT_SCHEDULE -> POST row passes authz (not 403)")
  void postRow_submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            post(ROWS)
                .param("millId", "543")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(ROW_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE -> PUT row 403 problem+json")
  void putRow_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put("/api/v1/schedule4/locations/8020/rows/999999")
                .param("millId", "543")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(ROW_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER holds EDIT_SCHEDULE -> PUT row passes authz (not 403)")
  void putRow_submitter_passesAuthorization() throws Exception {
    // Submitter clears the EDIT_SCHEDULE gate; row 999999 is not a sub-page row of 8020, so the
    // request proceeds past authz to a 404 (never 403) — the authz contract this IT asserts.
    mockMvc
        .perform(
            put("/api/v1/schedule4/locations/8020/rows/999999")
                .param("millId", "543")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(ROW_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isNotFound());
  }

  // -----------------------------------------------------------------------------------------
  // The ADMIN row of the role×status matrix (Story 16.1; added on the #427 review). Mill 740/2021
  // is 1–10 'V' and silviculture 'D' (R__51) — so a gate that read the wrong track's column would
  // see Draft, refuse the administrator, and every test below would fail on a 409 instead of
  // passing vacuously. The shared unit truth table proves the component; these prove THIS
  // schedule's wiring to it, on the write verb AND on DELETE.
  // -----------------------------------------------------------------------------------------

  /** A CREATE body — no id, so the admin write adds its own location rather than touching 8090. */
  private static final String CREATE_BODY =
      """
      { "revisionCount": 0, "name": "Verified Correction Dump",
        "categories": [ { "code": 40, "volume": 100, "cost": 5000, "distance": null } ] }
      """;

  @Test
  @DisplayName("ILCR_ADMIN WRITES at a VERIFIED track -> 2xx, and the track stays 'V' (AD-9)")
  void admin_writesAtVerified() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "740")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(CREATE_BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        // The correction must not move the track, and the echo must report the status the gate
        // actually read — not a STATUS_DRAFT literal passed in its place.
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN DELETES a location at a VERIFIED track -> 2xx (the correction path)")
  void admin_deletesAtVerified() throws Exception {
    // Location 8090 is R__51's seeded delete target on this mill, so this removes a real row rather
    // than exercising the idempotent no-op arm. A DELETE still holding the pre-16.1 Draft-only
    // literal answers 409 here while its sibling PUT passes — the divergence a refused-at-Draft
    // probe cannot see, because Draft-only and the matrix agree an admin may not write at 'D'.
    mockMvc
        .perform(
            delete(ENDPOINT)
                .param("millId", "740")
                .param("year", "2021")
                .param("id", "8090")
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
                .param("millId", "740")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(CREATE_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }
}
