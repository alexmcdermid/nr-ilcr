package ca.bc.gov.nrs.ilcr.schedule7a;

import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
 * Story 12.1/12.2 acceptance — authorization (AD-7) on every Schedule 7A endpoint: {@code
 * VIEW_SCHEDULE} for the GET read and the POST check-status, {@code EDIT_SCHEDULE} for the
 * POST/PUT/ DELETE bridge writes. Security ON: drives the real {@code oauth2ResourceServer} chain +
 * {@code @PreAuthorize}, with authorities derived through the production {@link
 * FamJwtAuthenticationConverter}.
 *
 * <p>The two production roles both hold VIEW+EDIT, so the write coverage asserts (a) an
 * unauthorized caller (no group / a foreign group) is denied 403 on each write, and (b) an
 * authorized role clears {@code @PreAuthorize} — proven with non-mutating requests (unknown id →
 * 404, check-status → 200) so this class, which has no per-test cleanup, never writes to the shared
 * fixture. Write-body-shaped requests carry a VALID body so a 403 comes from authorization, not
 * from bean validation (which is evaluated during argument resolution, before
 * {@code @PreAuthorize}).
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Schedule 7A — authorization on VIEW_SCHEDULE / EDIT_SCHEDULE (AC6)")
class Schedule7aAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule7a";
  private static final String BRIDGES = ENDPOINT + "/bridges";
  private static final String CHECK_STATUS = ENDPOINT + "/check-status";

  /** Since #359 the endpoint requires the on-screen body; its content is irrelevant to authz. */
  private static final String CHECK_BODY = "{\"bridges\":[]}";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  /**
   * A valid bridge body (default + OnUpdate groups) so a denial is authorization, not validation.
   */
  private static final String VALID_BODY =
      """
      {
        "locationName": "AuthZ Probe", "builtDate": "2020-06",
        "constructionTypeCode": "N", "superstructureTypeCode": "STL", "deckTypeCode": "WD",
        "abutmentTypeCode": "CONC", "loadRatingCode": "L100",
        "lifeSpan": 50, "abutmentHeight": 5.0, "length": 20.0, "width": 4.0, "distance": 12,
        "sitePlanCost": 1000, "superstructureMaterialCost": 5000, "superstructureDeliverCost": 500,
        "superstructureInstallCost": 800, "abutmentMaterialCost": 3000, "abutmentDeliverCost": 300,
        "abutmentInstallCost": 400, "approachCost": 700, "afterInstallCost": 200, "otherCost": 100,
        "comments": null, "revisionCount": 0
      }
      """;

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no group -> 403 ProblemDetail")
  void noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", "514")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("foreign group -> 403 ProblemDetail")
  void foreignGroup_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", "514")
                .param("year", "2021")
                .with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> passes authz (200)")
  void submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT).param("millId", "514").param("year", "2021").with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  // --- Writes require EDIT_SCHEDULE (POST/PUT/DELETE bridges)
  // -------------------------------------

  @Test
  @DisplayName("add without a group -> 403 (EDIT_SCHEDULE)")
  void addBridge_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            post(BRIDGES)
                .param("millId", "514")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("add with a foreign group -> 403 (EDIT_SCHEDULE)")
  void addBridge_foreignGroup_returns403() throws Exception {
    mockMvc
        .perform(
            post(BRIDGES)
                .param("millId", "514")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("correct without a group -> 403 (EDIT_SCHEDULE)")
  void updateBridge_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(BRIDGES + "/7601")
                .param("millId", "514")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("save-all without a group -> 403 (EDIT_SCHEDULE)")
  void saveAllBridges_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(BRIDGES)
                .param("millId", "514")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(saveAllBody())
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("save-all with a foreign group -> 403 (EDIT_SCHEDULE)")
  void saveAllBridges_foreignGroup_returns403() throws Exception {
    mockMvc
        .perform(
            put(BRIDGES)
                .param("millId", "514")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(saveAllBody())
                .with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden());
  }

  /** A one-entry save-all body wrapping {@link #VALID_BODY}; never reached on a 403 path. */
  private static String saveAllBody() {
    return "{\"bridges\": [{\"bridgeReportId\": 7601, \"bridge\": " + VALID_BODY + "}]}";
  }

  @Test
  @DisplayName("delete without a group -> 403 (EDIT_SCHEDULE)")
  void deleteBridge_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            delete(BRIDGES + "/7601")
                .param("millId", "514")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER clears EDIT_SCHEDULE on a write (unknown id -> 404, not 403)")
  void submitter_passesWriteAuthorization() throws Exception {
    // A non-mutating probe: authorized, so it clears @PreAuthorize and reaches the 404 branch
    // (unknown bridge id) rather than being denied — and it writes nothing to the shared fixture.
    mockMvc
        .perform(
            put(BRIDGES + "/888888")
                .param("millId", "514")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isNotFound());
  }

  // --- Check Status requires VIEW_SCHEDULE (POST check-status)
  // ------------------------------------

  @Test
  @DisplayName("check-status without a group -> 403 (VIEW_SCHEDULE)")
  void checkStatus_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            post(CHECK_STATUS)
                .contentType(MediaType.APPLICATION_JSON)
                .content(CHECK_BODY)
                .param("millId", "514")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> check-status passes authz (200)")
  void submitter_passesCheckStatusAuthorization() throws Exception {
    mockMvc
        .perform(
            post(CHECK_STATUS)
                .contentType(MediaType.APPLICATION_JSON)
                .content(CHECK_BODY)
                .param("millId", "514")
                .param("year", "2021")
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  // -----------------------------------------------------------------------------------------
  // The ADMIN row of the role×status matrix (Story 16.1; added on the #427 review). Mill 742/2021
  // is 1–10 'V' and silviculture 'D' (R__51) — so a gate that read the wrong track's column would
  // see Draft, refuse the administrator, and every test below would fail on a 409 instead of
  // passing vacuously. The shared unit truth table proves the component; these prove THIS
  // schedule's wiring to it, on the write verb AND on DELETE.
  // -----------------------------------------------------------------------------------------

  @Test
  @DisplayName("ILCR_ADMIN WRITES at a VERIFIED track -> 2xx, and the track stays 'V' (AD-9)")
  void admin_writesAtVerified() throws Exception {
    mockMvc
        .perform(
            post(BRIDGES)
                .param("millId", "742")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        // The correction must not move the track, and the echo must report the status the gate
        // actually read — not a STATUS_DRAFT literal passed in its place.
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN DELETES a bridge at a VERIFIED track -> 2xx (the correction path)")
  void admin_deletesAtVerified() throws Exception {
    // Bridge 7660 is R__51's seeded delete target on this mill, so this removes a real row rather
    // than exercising the idempotent no-op arm. A DELETE still holding the pre-16.1 Draft-only
    // literal answers 409 here while its sibling POST passes — the divergence a refused-at-Draft
    // probe cannot see, because Draft-only and the matrix agree an admin may not write at 'D'.
    mockMvc
        .perform(
            delete(BRIDGES + "/7660")
                .param("millId", "742")
                .param("year", "2021")
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        .andExpect(jsonPath("$.trackStatus", is("V")));
  }

  @Test
  @DisplayName("A SUBMITTER at that same VERIFIED track -> 409: only the ministry corrects")
  void submitter_refusedAtVerified() throws Exception {
    // The other half of the row. Without it, admin_writesAtVerified alone would also pass if the
    // gate had simply been widened to "anyone may edit at V".
    mockMvc
        .perform(
            post(BRIDGES)
                .param("millId", "742")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }
}
