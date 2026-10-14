package ca.bc.gov.nrs.ilcr.schedule5;

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
 * Story 7.2 acceptance — authorization on the Schedule 5 writes (AC7; AD-7). Security ON, driving
 * the real {@code oauth2ResourceServer} chain and {@code @PreAuthorize}: {@code EDIT_SCHEDULE} on
 * POST/PUT/DELETE, {@code VIEW_SCHEDULE} on {@code POST /check-status}. Authorities come from the
 * PRODUCTION {@link FamJwtAuthenticationConverter}, not a hand-built list, so a change to the
 * group-to-authority mapping fails here.
 *
 * <p><strong>The 403 bodies are VALID on purpose.</strong> {@code @Valid} body binding runs during
 * argument resolution, BEFORE {@code @PreAuthorize} fires, so an invalid body would yield 400 and
 * the test would pass for the wrong reason — proving nothing about authorization.
 *
 * <p><strong>Mill 676 is this class's own fixture, and its track is deliberately {@code
 * 'S'}.</strong> A submitter there gets 409 from the editability matrix: proof that
 * {@code @PreAuthorize} let it through and the domain gate — not authorization — stopped it. An
 * ADMIN at the same mill is the other half of that matrix and legitimately WRITES, which is why
 * this mill must stay owned by this class. Giving this class its own mill is the 8.2/12.2 lesson —
 * these probes used to fire at a year another suite's lock target owned, so an
 * {@code @PreAuthorize} regression mutated that test's fixture instead of failing here.
 *
 * <p><strong>Coverage gap (inherited, recorded on 25.2):</strong> a "holds VIEW but not EDIT → 403"
 * case is unreachable today because both shipped roles hold {@code EDIT_SCHEDULE}. It becomes
 * testable when the FAM auth story (DL-6) introduces a narrower view-only role.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Schedule 5 writes — authorization on EDIT_SCHEDULE / VIEW_SCHEDULE (AC7)")
class Schedule5WriteAuthorizationIT extends AbstractOracleIT {

  private static final String CAMPS = "/api/v1/schedule5/camps";
  private static final String CHECK_STATUS = "/api/v1/schedule5/check-status";
  private static final String PROBLEM_JSON = "application/problem+json";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  /** A VALID camp body — so a 403 fires at {@code @PreAuthorize}, not at {@code @Valid}. */
  private static final String VALID_BODY =
      """
      {"campName":"Authz Camp","isolatedCamp":false,"revisionCount":0}
      """;

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("POST /camps with no group -> 403")
  void addCamp_noGroup_returns403() throws Exception {
    mockMvc
        .perform(
            post(CAMPS)
                .with(csrf())
                .param("millId", "676")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));
  }

  @Test
  @DisplayName("PUT /camps/{campId} with no group -> 403")
  void updateCamp_noGroup_returns403() throws Exception {
    mockMvc
        .perform(
            put(CAMPS + "/8217")
                .with(csrf())
                .param("millId", "676")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("DELETE /camps/{campId} with no group -> 403")
  void deleteCamp_noGroup_returns403() throws Exception {
    mockMvc
        .perform(
            delete(CAMPS + "/8217")
                .with(csrf())
                .param("millId", "676")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("POST /check-status with no group -> 403 (VIEW_SCHEDULE required)")
  void checkStatus_noGroup_returns403() throws Exception {
    mockMvc
        .perform(
            post(CHECK_STATUS)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"camp\":null}")
                .with(csrf())
                .param("millId", "672")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName(
      "check-status as ILCR_SUBMITTER -> 200; it needs only VIEW_SCHEDULE and no Draft track")
  void checkStatus_submitter_returns200() throws Exception {
    mockMvc
        .perform(
            post(CHECK_STATUS)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"camp\":null}")
                .with(csrf())
                .param("millId", "672")
                .param("year", "2021")
                .with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.outcome", is("MET")));
  }

  @Test
  @DisplayName("check-status runs on a NON-DRAFT mill too -> 200 (VIEW-gated, not Draft-gated)")
  void checkStatus_nonDraftMill_returns200() throws Exception {
    // Mill 676 is track 'S'. If check-status were ever Draft-gated by copy-paste from the writes,
    // this would 409 — and a licensee would lose the ability to review a submitted schedule.
    mockMvc
        .perform(
            post(CHECK_STATUS)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"camp\":null}")
                .with(csrf())
                .param("millId", "676")
                .param("year", "2021")
                .with(canonicalSubmitter()))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER at a Submitted track -> authz passes (not 403); matrix -> 409")
  void submitter_passesEditAuthorization() throws Exception {
    mockMvc
        .perform(
            post(CAMPS)
                .with(csrf())
                .param("millId", "676")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }

  @Test
  @DisplayName("ILCR_ADMIN WRITES at a Submitted track -> 201/200, the correction path (AD-9)")
  void admin_writesAtSubmitted() throws Exception {
    mockMvc
        .perform(
            post(CAMPS)
                .with(csrf())
                .param("millId", "676")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        // The correction must not move the track — it stays Submitted.
        .andExpect(jsonPath("$.trackStatus", is("S")))
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN at a DRAFT track -> 409: the mill still owns its draft (AD-9)")
  void admin_refusedAtDraft() throws Exception {
    mockMvc
        .perform(
            post(CAMPS)
                .with(csrf())
                .param("millId", "672")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isConflict());
  }

  @Test
  @DisplayName("DELETE as an authorized caller also reaches the Draft gate, not a 403")
  void delete_passesEditAuthorization() throws Exception {
    mockMvc
        .perform(
            delete(CAMPS + "/8217")
                .with(csrf())
                .param("millId", "676")
                .param("year", "2021")
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }

  // -----------------------------------------------------------------------------------------
  // The VERIFIED row of the matrix (Story 16.1). Mill 734/2021 is 1–10 'V' and silviculture 'D'
  // (R__50) — so a gate that read the wrong track's column would see Draft, refuse the
  // administrator, and every test below would fail on a 409 instead of passing vacuously.
  // -----------------------------------------------------------------------------------------

  @Test
  @DisplayName("ILCR_ADMIN WRITES at a VERIFIED track -> 2xx, and the track stays 'V' (AD-9)")
  void admin_writesAtVerified() throws Exception {
    mockMvc
        .perform(
            post(CAMPS)
                .with(csrf())
                .param("millId", "734")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        // The echo must report the status the gate actually read. Before 16.1 the post-write echo
        // passed a STATUS_DRAFT literal, so this assertion would have read "D" on a Verified
        // report — and recomputed editable for the wrong status.
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN UPDATES at a VERIFIED track -> 2xx (the correction path)")
  void admin_updatesAtVerified() throws Exception {
    mockMvc
        .perform(
            put(CAMPS + "/8250")
                .with(csrf())
                .param("millId", "734")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"campName":"Corrected At Verified","isolatedCamp":false,"revisionCount":0}
                    """)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        .andExpect(jsonPath("$.trackStatus", is("V")));
  }

  @Test
  @DisplayName("ILCR_ADMIN DELETES at a VERIFIED track -> 2xx (the correction path)")
  void admin_deletesAtVerified() throws Exception {
    mockMvc
        .perform(
            delete(CAMPS + "/8251")
                .with(csrf())
                .param("millId", "734")
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
            post(CAMPS)
                .with(csrf())
                .param("millId", "734")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }
}
