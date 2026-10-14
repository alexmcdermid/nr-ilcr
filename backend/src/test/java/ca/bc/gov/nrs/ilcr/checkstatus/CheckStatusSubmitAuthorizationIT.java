package ca.bc.gov.nrs.ilcr.checkstatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test — Story 15.3 AC 5: authorization on {@code SUBMIT_REPORT} plus mill scope for the
 * submit endpoint (AD-6/AD-7, PRD FR5 "ministry users cannot submit on a Licensee's behalf,
 * regardless of UI state"). Security ON. An ADMIN-only caller is 403'd by the action check before
 * any read; a submitter with no active assignment to the mill is 403'd by the shared guard's
 * mill-scope check; an ADMIN+SUBMITTER retains the action but remains bound to that same SUBMITTER
 * scope. The canonical associated submitter REACHES the transition (proven by the transition's own
 * 409 on an already-Submitted anchor), so nothing is mutated here. Draft offer and denial cases use
 * the read-only 515 anchor; mill 780 belongs exclusively to {@code CheckStatusSubmitIT} and is
 * permanently submitted there.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName(
    "POST /api/v1/check-status/submit — authorization on SUBMIT_REPORT + mill scope (15.3)")
class CheckStatusSubmitAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/check-status/submit";
  private static final long DRAFT_ANCHOR = 515L;
  private static final String PROBLEM_JSON = "application/problem+json";
  private static final String NOT_DRAFT =
      "Schedules 1-10 are no longer in Draft and cannot be submitted.";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;
  @Autowired private JdbcTemplate jdbc;

  private static MockHttpServletRequestBuilder submit(String mill) {
    return post(ENDPOINT).param("millId", mill).param("year", "2021");
  }

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  /** A submitter with NO xref association to any mill (32-char GUID, never seeded). */
  private RequestPostProcessor unassociatedSubmitter() {
    return jwt()
        .jwt(
            j ->
                j.claim("idir_user_guid", "UNASSOCIATEDSUBMITTERXXXX0000001")
                    .claim("identity_provider", "azureidir")
                    .claim("client_roles", List.of("ILCR_SUBMITTER")))
        .authorities(new SimpleGrantedAuthority("SUBMITTER"));
  }

  private RequestPostProcessor dualRole(String userGuid) {
    return jwt()
        .jwt(
            j ->
                j.claim("idir_user_guid", userGuid)
                    .claim("identity_provider", "azureidir")
                    .claim("client_roles", List.of("ILCR_ADMIN", "ILCR_SUBMITTER")))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private RequestPostProcessor admin() {
    return jwtWithGroups(List.of("ILCR_ADMIN"));
  }

  private String statusOf(long mill) {
    return jdbc.queryForObject(
        "SELECT ILCR_MILL_REPORT_STATUS_CODE || '/' || REVISION_COUNT || '/' || UPDATE_USERID"
            + " FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
        mill);
  }

  @Test
  @DisplayName("ADMIN-only caller on a Draft mill -> 403 problem+json, nothing written")
  void admin_returns403_writesNothing() throws Exception {
    String before = statusOf(DRAFT_ANCHOR);

    mockMvc
        .perform(submit(String.valueOf(DRAFT_ANCHOR)).with(admin()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));

    assertThat(statusOf(DRAFT_ANCHOR)).isEqualTo(before).startsWith("D/0/");
  }

  @Test
  @DisplayName("no group at all -> 403")
  void noPermission_returns403() throws Exception {
    mockMvc
        .perform(submit(String.valueOf(DRAFT_ANCHOR)).with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER not associated to the mill -> 403 by mill scope, nothing written")
  void unassociatedSubmitter_returns403_writesNothing() throws Exception {
    String before = statusOf(DRAFT_ANCHOR);

    mockMvc
        .perform(submit(String.valueOf(DRAFT_ANCHOR)).with(unassociatedSubmitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));

    assertThat(statusOf(DRAFT_ANCHOR)).isEqualTo(before);
  }

  @Test
  @DisplayName(
      "canonical associated ILCR_SUBMITTER reaches the transition: an already-Submitted mill answers"
          + " the guard's 409, not a 403")
  void associatedSubmitter_reachesTheTransition() throws Exception {
    mockMvc
        .perform(submit("517").with(canonicalSubmitter()))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        .andExpect(jsonPath("$.detail", is(NOT_DRAFT)));
  }

  @Test
  @DisplayName("dual-role caller without a submitter assignment cannot submit for the mill")
  void unassociatedDualRole_returns403_writesNothing() throws Exception {
    String before = statusOf(DRAFT_ANCHOR);

    mockMvc
        .perform(
            submit(String.valueOf(DRAFT_ANCHOR)).with(dualRole("UNASSOCIATEDSUBMITTERXXXX0000001")))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));

    assertThat(statusOf(DRAFT_ANCHOR)).isEqualTo(before);
  }

  @Test
  @DisplayName("dual-role caller with a submitter assignment reaches the transition")
  void associatedDualRole_reachesTheTransition() throws Exception {
    mockMvc
        .perform(submit("517").with(dualRole(CANONICAL_SUBMITTER_GUID)))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        .andExpect(jsonPath("$.detail", is(NOT_DRAFT)));
  }

  @Test
  @DisplayName("dual-role caller without a submitter assignment does not see Submit offered")
  void unassociatedDualRole_canViewButCannotSubmit() throws Exception {
    mockMvc
        .perform(
            get("/api/v1/check-status")
                .param("millId", String.valueOf(DRAFT_ANCHOR))
                .param("year", "2021")
                .with(dualRole("UNASSOCIATEDSUBMITTERXXXX0000001")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.schedules1To10.canSubmit", is(false)));
  }

  @Test
  @DisplayName("dual-role caller with a submitter assignment sees Submit offered at Draft")
  void associatedDualRole_canSubmit() throws Exception {
    mockMvc
        .perform(
            get("/api/v1/check-status")
                .param("millId", String.valueOf(DRAFT_ANCHOR))
                .param("year", "2021")
                .with(dualRole(CANONICAL_SUBMITTER_GUID)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.schedules1To10.canSubmit", is(true)));
  }

  // --- Schedule 11 submit (Story 26.1 AC 6): the same action, the same Submit-specific scope
  // ------

  private static final String SCHEDULE_11_ENDPOINT = "/api/v1/check-status/schedule11/submit";

  /**
   * R__57's silviculture-Draft mill whose gate fails: a request that got through writes nothing.
   */
  private static final long SCHEDULE_11_DRAFT_ANCHOR = 785L;

  private static final String SCHEDULE_11_NOT_DRAFT =
      "Schedule 11 is no longer in Draft and cannot be submitted.";

  private static MockHttpServletRequestBuilder submitSchedule11(long mill) {
    return post(SCHEDULE_11_ENDPOINT).param("millId", String.valueOf(mill)).param("year", "2021");
  }

  private String silvicultureStatusOf(long mill) {
    return jdbc.queryForObject(
        "SELECT MILL_SILVICULTUR_STATUS_CODE || '/' || REVISION_COUNT || '/' || UPDATE_USERID"
            + " FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
        mill);
  }

  @Test
  @DisplayName("26.1: ADMIN-only caller -> 403 on the Schedule 11 submit, nothing written")
  void schedule11_admin_returns403_writesNothing() throws Exception {
    String before = silvicultureStatusOf(SCHEDULE_11_DRAFT_ANCHOR);

    mockMvc
        .perform(submitSchedule11(SCHEDULE_11_DRAFT_ANCHOR).with(admin()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));

    assertThat(silvicultureStatusOf(SCHEDULE_11_DRAFT_ANCHOR)).isEqualTo(before).startsWith("D/0/");
  }

  @Test
  @DisplayName("26.1: ILCR_SUBMITTER not associated to the mill -> 403 on the Schedule 11 submit")
  void schedule11_unassociatedSubmitter_returns403() throws Exception {
    String before = silvicultureStatusOf(SCHEDULE_11_DRAFT_ANCHOR);

    mockMvc
        .perform(submitSchedule11(SCHEDULE_11_DRAFT_ANCHOR).with(unassociatedSubmitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));

    assertThat(silvicultureStatusOf(SCHEDULE_11_DRAFT_ANCHOR)).isEqualTo(before);
  }

  @Test
  @DisplayName("26.1: dual-role caller without a submitter assignment -> 403 on Schedule 11 too")
  void schedule11_unassociatedDualRole_returns403() throws Exception {
    String before = silvicultureStatusOf(SCHEDULE_11_DRAFT_ANCHOR);

    mockMvc
        .perform(
            submitSchedule11(SCHEDULE_11_DRAFT_ANCHOR)
                .with(dualRole("UNASSOCIATEDSUBMITTERXXXX0000001")))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));

    assertThat(silvicultureStatusOf(SCHEDULE_11_DRAFT_ANCHOR)).isEqualTo(before);
  }

  @Test
  @DisplayName(
      "26.1: the associated submitter and dual-role caller both REACH the Schedule 11 transition"
          + " (786 is already S -> its own 409, not a 403)")
  void schedule11_associatedCallers_reachTheTransition() throws Exception {
    mockMvc
        .perform(submitSchedule11(786).with(canonicalSubmitter()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(SCHEDULE_11_NOT_DRAFT)));
    mockMvc
        .perform(submitSchedule11(786).with(dualRole(CANONICAL_SUBMITTER_GUID)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(SCHEDULE_11_NOT_DRAFT)));
  }

  @Test
  @DisplayName(
      "26.1 AC 7: schedule11.canSubmit follows the same scope — offered to the assigned dual-role"
          + " caller, not to the unassigned one, never to ADMIN alone")
  void schedule11_canSubmitFollowsTheSubmitScope() throws Exception {
    mockMvc
        .perform(
            get("/api/v1/check-status")
                .param("millId", String.valueOf(SCHEDULE_11_DRAFT_ANCHOR))
                .param("year", "2021")
                .with(dualRole(CANONICAL_SUBMITTER_GUID)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.schedule11.canSubmit", is(true)));
    mockMvc
        .perform(
            get("/api/v1/check-status")
                .param("millId", String.valueOf(SCHEDULE_11_DRAFT_ANCHOR))
                .param("year", "2021")
                .with(dualRole("UNASSOCIATEDSUBMITTERXXXX0000001")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.schedule11.canSubmit", is(false)));
    mockMvc
        .perform(
            get("/api/v1/check-status")
                .param("millId", String.valueOf(SCHEDULE_11_DRAFT_ANCHOR))
                .param("year", "2021")
                .with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.schedule11.canSubmit", is(false)));
  }
}
