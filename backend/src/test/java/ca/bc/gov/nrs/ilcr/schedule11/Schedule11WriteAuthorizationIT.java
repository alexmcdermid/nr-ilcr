package ca.bc.gov.nrs.ilcr.schedule11;

import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
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
 * Story 25.2 acceptance — authorization on the Schedule 11 writes (AC8; AD-7). Security ON: drives
 * the real {@code oauth2ResourceServer} chain + {@code @PreAuthorize} ({@code EDIT_SCHEDULE} on
 * POST/PUT/DELETE, {@code VIEW_SCHEDULE} on check-status), authorities via the production {@link
 * FamJwtAuthenticationConverter}.
 *
 * <p>Bodies on the 403 write tests are VALID because {@code @Valid} body binding runs during
 * argument resolution BEFORE {@code @PreAuthorize} fires — an invalid body would yield 400, not the
 * 403 under test. The submitter "authorized" proof POSTs to a non-Draft mill (615/'S'): authz
 * passes so the request is NOT 403, and the editability matrix rejects it 409 WITHOUT mutating
 * anything — no fixture churn.
 *
 * <p><strong>That no-mutation trick stops working for the administrator (Story 16.1).</strong> An
 * ILCR_ADMIN at 'S' or 'V' now legitimately WRITES, so the admin arm cannot borrow a shared refusal
 * fixture — 615 is read by sibling suites and would be corrupted. Mills <strong>735</strong>
 * (silviculture 'S') and <strong>736</strong> (silviculture 'V') are seeded by {@code R__50} and
 * owned solely by this class for that reason. Both carry 'D' on the 1–10 column, so the per-track
 * evaluation is falsifiable rather than assumed.
 *
 * <p><b>Coverage gap (recorded):</b> a "holds VIEW but not EDIT → 403" case is unreachable today —
 * both shipped roles ({@code ILCR_SUBMITTER}, {@code ILCR_ADMIN}) hold {@code EDIT_SCHEDULE}. It
 * becomes testable when a narrower (view-only) role exists.
 *
 * <p>TODO(DL-6, FAM auth story): when the FAM auth story introduces a narrower (view-only) role,
 * add a "holds VIEW_SCHEDULE but not EDIT_SCHEDULE → 403 on POST/PUT/DELETE" test here. The full
 * action-key mapping / narrower roles land with that story (see implementation-readiness-report
 * DL-6).
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Schedule 11 writes — authorization on EDIT_SCHEDULE / VIEW_SCHEDULE (AC8)")
class Schedule11WriteAuthorizationIT extends AbstractOracleIT {

  private static final String LOCATIONS = "/api/v1/schedule11/locations";
  private static final String CHECK_STATUS = "/api/v1/schedule11/check-status";
  private static final String PROBLEM_JSON = "application/problem+json";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  // A valid create body — so the 403 fires at @PreAuthorize, not at @Valid (which runs first).
  private static final String VALID_BODY =
      """
        {"location":"Authz Probe","enhancedIndicator":false,"biogeoclimaticCatalogueId":8801,
         "netArea":10.0,"revisionCount":0}
        """;

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("POST with no group -> 403")
  void addLocation_noGroup_returns403() throws Exception {
    mockMvc
        .perform(
            post(LOCATIONS)
                .with(csrf())
                .param("millId", "614")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));
  }

  // MIGRATED by Story 26.2: the per-row PUT and DELETE are retired for the page-level save. Both
  // arms are kept — one carries an update, one a delete — so neither half of the save can lose its
  // EDIT_SCHEDULE gate unnoticed.

  @Test
  @DisplayName("page-level save carrying an update, with no group -> 403")
  void saveAll_updateWithNoGroup_returns403() throws Exception {
    mockMvc
        .perform(
            put(LOCATIONS)
                .with(csrf())
                .param("millId", "614")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"locations\":[{\"basicSilvicultureReportId\":9201,\"location\":"
                        + VALID_BODY
                        + "}],\"deletedIds\":[]}")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("page-level save carrying a delete, with no group -> 403")
  void saveAll_deleteWithNoGroup_returns403() throws Exception {
    mockMvc
        .perform(
            put(LOCATIONS)
                .with(csrf())
                .param("millId", "614")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"locations\":[],\"deletedIds\":[9201]}")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("check-status with no group -> 403 (VIEW_SCHEDULE required)")
  void checkStatus_noGroup_returns403() throws Exception {
    mockMvc
        .perform(
            post(CHECK_STATUS)
                .with(csrf())
                .param("millId", "616")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName(
      "ILCR_SUBMITTER holds EDIT_SCHEDULE -> authz passes (not 403); non-Draft gate -> 409")
  void submitter_passesEditAuthorization() throws Exception {
    mockMvc
        .perform(
            post(LOCATIONS)
                .with(csrf())
                .param("millId", "615")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict()); // 409 not-editable — proves authz passed, no mutation
  }

  @Test
  @DisplayName("ILCR_ADMIN at a Draft track -> authz passes (not 403); matrix -> 409")
  void admin_refusedAtSilvicultureDraft() throws Exception {
    // 614/2021 carries silviculture 'D': authz passes so the request is NOT 403, and the matrix
    // refuses an administrator at Draft on this track too -- 409, nothing written.
    mockMvc
        .perform(
            post(LOCATIONS)
                .with(csrf())
                .param("millId", "614")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isConflict());
  }

  // -----------------------------------------------------------------------------------------
  // The positive arm on the SILVICULTURE track (Story 16.1). Mills 735 and 736 (R__50) carry the
  // status under test on the silviculture column and 'D' on the 1–10 column — the inverse of mill
  // 615. That pairing is what makes the track split falsifiable: legacy duplicated
  // disableUserInput() verbatim per track and changed only the getter it read, so a gate reading
  // ILCR_MILL_REPORT_STATUS_CODE here would see Draft, refuse the administrator, and fail these.
  // -----------------------------------------------------------------------------------------

  @Test
  @DisplayName("ILCR_ADMIN WRITES at a SUBMITTED silviculture track -> 2xx, track stays 'S'")
  void admin_writesAtSilvicultureSubmitted() throws Exception {
    mockMvc
        .perform(
            post(LOCATIONS)
                .with(csrf())
                .param("millId", "735")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        // 'S' — not the 'D' sitting on this mill's 1–10 column, and not the STATUS_DRAFT literal
        // the pre-16.1 echo passed its response builder.
        .andExpect(jsonPath("$.trackStatus", is("S")))
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN WRITES at a VERIFIED silviculture track -> 2xx, track stays 'V'")
  void admin_writesAtSilvicultureVerified() throws Exception {
    mockMvc
        .perform(
            post(LOCATIONS)
                .with(csrf())
                .param("millId", "736")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("A SUBMITTER at that same SUBMITTED silviculture track -> 409")
  void submitter_refusedAtSilvicultureSubmitted() throws Exception {
    // The other half of the row: the mill has handed the report over, so it is read-only to the
    // mill. Without this, the admin case above would also pass on a gate simply widened to "anyone
    // may edit at S".
    mockMvc
        .perform(
            post(LOCATIONS)
                .with(csrf())
                .param("millId", "735")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }

  @Test
  @DisplayName("ILCR_ADMIN DELETES at a VERIFIED silviculture track -> 2xx (the correction path)")
  void admin_deletesAtSilvicultureVerified() throws Exception {
    // The positive DELETE arm. This suite proved the admin WRITE at both editable statuses but
    // never the delete, and the two are separate seams: the service threads its own
    // EditableStatuses through each path, so a DELETE left on the pre-16.1 Draft-only literal
    // passes every refused-at-Draft probe here — Draft-only and the matrix agree that an
    // administrator may not write at 'D'. Location 9402 is R__50's seeded row on mill 736, so this
    // removes a real row, and it is not the row admin_writesAtSilvicultureVerified creates, so the
    // two arms stay independent of JUnit method order.
    // MIGRATED by Story 26.2 onto the page-level save (the per-row DELETE is retired).
    mockMvc
        .perform(
            put(LOCATIONS)
                .with(csrf())
                .param("millId", "736")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"locations\":[],\"deletedIds\":[9402]}")
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        .andExpect(jsonPath("$.trackStatus", is("V")));
  }
}
