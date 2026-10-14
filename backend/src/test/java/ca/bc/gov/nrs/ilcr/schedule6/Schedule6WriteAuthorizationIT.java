package ca.bc.gov.nrs.ilcr.schedule6;

import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
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
 * Story 8.2/Task 8 acceptance — authorization on the Schedule 6 writes (AC8; AD-7). Security ON:
 * drives the real {@code oauth2ResourceServer} chain + {@code @PreAuthorize} ({@code EDIT_SCHEDULE}
 * on the writes, {@code VIEW_SCHEDULE} on check-status), authorities via the production {@link
 * FamJwtAuthenticationConverter}. The retired {@code PUT /records/{recordId}} and {@code PUT
 * /general-comments} no-group-403 cases dropped with their endpoints (Task 8) — the same {@code
 * EDIT_SCHEDULE} authorization requirement they proved is proven for every remaining Schedule 6
 * write here, including the whole-document {@code PUT /api/v1/schedule6} that replaced them.
 *
 * <p>Bodies on the 403 write tests are VALID because {@code @Valid} body binding runs during
 * argument resolution BEFORE {@code @PreAuthorize} fires — an invalid body would yield 400, not the
 * 403 under test. The "authorized" proof POSTs to the non-Draft mill (662/'S'): authz passes so the
 * request is NOT 403, and the service's Draft gate rejects it 409 WITHOUT mutating anything — no
 * fixture churn.
 *
 * <p>Mill <b>666</b> is this class's own fixture (V32), added at code review 2026-08-04. These
 * probes previously fired at 661/2021 — a year {@link Schedule6WriteIT} once used for its own
 * per-record edit tests (retired with {@code PUT /records/{recordId}}) — so a PreAuthorize
 * regression would have let a write land on that test's target and failed a different suite instead
 * of this one.
 *
 * <p><b>Coverage gap (inherited, recorded on 25.2):</b> a "holds VIEW but not EDIT → 403" case is
 * unreachable today — both shipped roles hold {@code EDIT_SCHEDULE}. It becomes testable when the
 * FAM auth story (DL-6) introduces a narrower view-only role.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Schedule 6 writes — authorization on EDIT_SCHEDULE / VIEW_SCHEDULE (AC8)")
class Schedule6WriteAuthorizationIT extends AbstractOracleIT {

  private static final String RECORDS = "/api/v1/schedule6/records";
  private static final String CHECK_STATUS = "/api/v1/schedule6/check-status";
  private static final String ENDPOINT = "/api/v1/schedule6";
  private static final String PROBLEM_JSON = "application/problem+json";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  // A valid record body — so a 403 fires at @PreAuthorize, not at @Valid (which runs first).
  // No revisionCount: RoadRecordRequest dropped that field (Task 8) since POST /records never
  // read it; sending one relied only on Boot's default FAIL_ON_UNKNOWN_PROPERTIES=false and would
  // 400-before-403 the moment that default ever flips (the exact silent-wrong-test failure mode
  // this class exists to avoid).
  private static final String VALID_BODY =
      """
        {"areaType":"01","supplyBlock":"01B","volume":10,"cost":100}
        """;

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("POST /records with no group -> 403")
  void addRecord_noGroup_returns403() throws Exception {
    mockMvc
        .perform(
            post(RECORDS)
                .with(csrf())
                .param("millId", "666")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));
  }

  @Test
  @DisplayName("DELETE /records/{id} with no group -> 403 (Task 3)")
  void deleteRecord_noGroup_returns403() throws Exception {
    mockMvc
        .perform(
            delete(RECORDS + "/8358")
                .with(csrf())
                .param("millId", "666")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));
  }

  @Test
  @DisplayName("PUT /api/v1/schedule6 (whole-document save, Task 5) with no group -> 403")
  void saveDocument_noGroup_returns403() throws Exception {
    // An empty records[] + null comment is a trivially valid body -- @Valid runs during argument
    // resolution BEFORE @PreAuthorize, so an invalid body would produce 400, not the 403 under
    // test (same rationale as the other write probes in this class).
    mockMvc
        .perform(
            put(ENDPOINT)
                .with(csrf())
                .param("millId", "666")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"generalComments\":null,\"records\":[]}")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));
  }

  @Test
  @DisplayName(
      "ILCR_SUBMITTER holds EDIT_SCHEDULE -> whole-document PUT authz passes (not 403); "
          + "non-Draft gate -> 409 (Task 5)")
  void submitter_passesSaveDocumentAuthorization() throws Exception {
    // 662/2021 (status 'S'): authz passes so the request is NOT 403, and the service's Draft gate
    // rejects it 409 WITHOUT mutating anything -- no fixture churn.
    mockMvc
        .perform(
            put(ENDPOINT)
                .with(csrf())
                .param("millId", "662")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"generalComments\":null,\"records\":[]}")
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }

  @Test
  @DisplayName("check-status with no group -> 403 (VIEW_SCHEDULE required)")
  void checkStatus_noGroup_returns403() throws Exception {
    // A valid (empty) body, same rationale as the write probes above: @Valid runs before
    // @PreAuthorize, and the body is required (Task 8) -- an absent one would 400, not 403.
    mockMvc
        .perform(
            post(CHECK_STATUS)
                .with(csrf())
                .param("millId", "663")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"generalComments\":null,\"records\":[]}")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("check-status with VIEW_SCHEDULE only in play (ILCR_SUBMITTER) -> 200")
  void checkStatus_submitter_returns200() throws Exception {
    // An empty records[] is the vacuous MET pass (Task 6/Task 8: the verdict is payload-only) --
    // this test is about authorization, not schedule data, so any valid body proves the point.
    mockMvc
        .perform(
            post(CHECK_STATUS)
                .with(csrf())
                .param("millId", "663")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"generalComments\":null,\"records\":[]}")
                .with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.outcome", is("MET")));
  }

  @Test
  @DisplayName(
      "ILCR_SUBMITTER holds EDIT_SCHEDULE -> authz passes (not 403); non-Draft gate -> 409")
  void submitter_passesEditAuthorization() throws Exception {
    mockMvc
        .perform(
            post(RECORDS)
                .with(csrf())
                .param("millId", "662")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict()); // 409 not-editable — authz passed, no mutation
  }

  @Test
  @DisplayName("ILCR_ADMIN at a Draft track -> authz passes (not 403); matrix -> 409")
  void admin_refusedAtDraft() throws Exception {
    // 666/2021 is this class's own DRAFT mill: authz passes so the request is NOT 403, and the
    // matrix refuses an administrator while the mill still owns its draft -- 409, nothing written.
    mockMvc
        .perform(
            post(RECORDS)
                .with(csrf())
                .param("millId", "666")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isConflict());
  }

  @Test
  @DisplayName(
      "ILCR_SUBMITTER holds EDIT_SCHEDULE -> DELETE authz passes (not 403); non-Draft gate -> 409"
          + " (Task 3)")
  void submitter_passesDeleteAuthorization() throws Exception {
    // 662/2021 (status 'S') + its seeded record 8321: authz passes so the request is NOT 403, and
    // the service's Draft gate rejects it 409 WITHOUT deleting anything -- no fixture churn.
    mockMvc
        .perform(
            delete(RECORDS + "/8321")
                .with(csrf())
                .param("millId", "662")
                .param("year", "2021")
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }

  // -----------------------------------------------------------------------------------------
  // The ADMIN row of the role×status matrix (Story 16.1; added on the #427 review). Mill 741/2021
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
            post(RECORDS)
                .with(csrf())
                .param("millId", "741")
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
  @DisplayName("ILCR_ADMIN DELETES a road record at a VERIFIED track -> 2xx (the correction path)")
  void admin_deletesAtVerified() throws Exception {
    // Record 8410 is R__51's seeded delete target on this mill, so this removes a real row rather
    // than exercising the idempotent no-op arm. A DELETE still holding the pre-16.1 Draft-only
    // literal answers 409 here while its sibling POST passes — the divergence a refused-at-Draft
    // probe cannot see, because Draft-only and the matrix agree an admin may not write at 'D'.
    mockMvc
        .perform(
            delete(RECORDS + "/8410")
                .with(csrf())
                .param("millId", "741")
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
            post(RECORDS)
                .with(csrf())
                .param("millId", "741")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }
}
