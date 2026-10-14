package ca.bc.gov.nrs.ilcr.checkstatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test — Story 18.1 AC 6: authorization on {@code SET_REPORT_STATUS} for both reversals
 * (AD-6/AD-7). Security ON.
 *
 * <p><strong>This is the forged-request arm.</strong> UC-CHK-018's slice catalogue records the gap
 * explicitly ({@code UC-CHK-018-slices.md:31}); UC-CHK-016 has no equivalent note, but {@code
 * CheckStatusMB.setToDraft()} calls the same private method, so the gap applies to {@code
 * S}&rarr;{@code D} by construction. Legacy hid both buttons from a Licensee and enforced nothing
 * below the view, so a request that never saw the button succeeded. Here the action check runs
 * first and the caller never reaches the transition.
 *
 * <p>Nothing here mutates: every arm is a 403, and each asserts the track status is unchanged
 * afterwards so a "denied" that had already written cannot pass. The mills are refused-arm mills
 * shared with {@code SetToDraftIT} / {@code SetToSubmitIT} — safe precisely because no test in any
 * of the three classes writes to them, which is what removes the ordering dependence rather than
 * merely hiding it.
 *
 * <p>The canonical submitter is used rather than an unassociated one on purpose: mill scope would
 * ALSO produce a 403, so an unassociated caller would pass this test for the wrong reason. {@code
 * R__56}'s prefix is below 70 exactly so {@code R__70}'s set-based association covers these mills
 * and the only thing left to deny is the missing action.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Check Status reversals — authorization on SET_REPORT_STATUS (Story 18.1)")
class SetReportStatusAuthorizationIT extends AbstractOracleIT {

  private static final String SET_TO_DRAFT = "/api/v1/check-status/set-to-draft";
  private static final String SET_TO_SUBMIT = "/api/v1/check-status/set-to-submit";
  private static final String PROBLEM_JSON = "application/problem+json";

  /** At Draft, all-met, and written by nothing in any suite. */
  private static final String READ_ONLY_MILL = "793";

  /** At Verified, all-met, and written by nothing in any suite. */
  private static final String VERIFIED_READ_ONLY_MILL = "794";

  private static final String NOT_VERIFIED =
      "Schedules 1-10 are no longer in Verified and cannot be set to Submit.";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;
  @Autowired private JdbcTemplate jdbc;

  private static MockHttpServletRequestBuilder reversal(String endpoint, String mill) {
    return post(endpoint).param("millId", mill).param("year", "2021");
  }

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private String trackStatus(String mill) {
    return jdbc.queryForObject(
        "SELECT ILCR_MILL_REPORT_STATUS_CODE FROM THE.ILCR_MILL_REPORT_STATUS"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
        Integer.valueOf(mill));
  }

  @Test
  @DisplayName("AC6: a Licensee is denied Set to Draft — 403 before any read, nothing written")
  void submitterCannotSetToDraft() throws Exception {
    mockMvc
        .perform(reversal(SET_TO_DRAFT, READ_ONLY_MILL).with(canonicalSubmitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));

    assertThat(trackStatus(READ_ONLY_MILL)).isEqualTo("D");
  }

  @Test
  @DisplayName("AC6: a Licensee is denied Set to Submit — 403 before any read, nothing written")
  void submitterCannotSetToSubmit() throws Exception {
    mockMvc
        .perform(reversal(SET_TO_SUBMIT, VERIFIED_READ_ONLY_MILL).with(canonicalSubmitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));

    assertThat(trackStatus(VERIFIED_READ_ONLY_MILL)).isEqualTo("V");
  }

  @Test
  @DisplayName("AC6: authorization runs BEFORE parameter validation — 403, not 400 ERR-001")
  void authorizationPrecedesParameterValidation() throws Exception {
    // A Licensee sending a request with no millId at all must not learn that the parameter was the
    // problem: the method-security check fires before the controller body runs, so there is no
    // path on which an unauthorized caller reaches MillContextService (CheckStatusApi:33).
    mockMvc
        .perform(post(SET_TO_DRAFT).with(canonicalSubmitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(post(SET_TO_SUBMIT).param("millId", "nonsense").with(canonicalSubmitter()))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("AC6: an unauthenticated caller is denied both reversals")
  void anonymousIsDenied() throws Exception {
    mockMvc.perform(reversal(SET_TO_DRAFT, READ_ONLY_MILL)).andExpect(status().isUnauthorized());
    mockMvc
        .perform(reversal(SET_TO_SUBMIT, VERIFIED_READ_ONLY_MILL))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("AC6: an ADMIN holds the action and REACHES the transition — proven by its 409")
  void adminReachesTheTransition() throws Exception {
    // The negative control the three arms above need. Without it they would all still pass if the
    // endpoint denied everyone. A refused-by-status 409 with the transition's own text proves the
    // caller got past authorization and past the context guard and was stopped by the rule under
    // test — and 797 is Submitted, so this writes nothing.
    mockMvc
        .perform(reversal(SET_TO_SUBMIT, "797").with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(NOT_VERIFIED)));

    assertThat(trackStatus("797")).isEqualTo("S");
  }

  // --- Story 26.3: Schedule 11 verify sits behind the same action
  // ----------------------------------

  private static final String VERIFY_11 = "/api/v1/check-status/schedule11/verify";

  /** R__59's silviculture-Draft refused-arm mill: written by nothing in any suite. */
  private static final String SCH11_DRAFT_MILL = "809";

  /** R__59's silviculture-Verified refused-arm mill: written by nothing in any suite. */
  private static final String SCH11_VERIFIED_MILL = "810";

  private static final String SUBMISSION_ERROR =
      "An error has been found submitting schedules. The error details have been logged. Please"
          + " contact ILCR application support.";

  private String silvicultureStatus(String mill) {
    return jdbc.queryForObject(
        "SELECT MILL_SILVICULTUR_STATUS_CODE FROM THE.ILCR_MILL_REPORT_STATUS"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
        Integer.valueOf(mill));
  }

  @Test
  @DisplayName("26.3 AC 6: a Licensee is denied Schedule 11 Verify — 403, nothing written")
  void submitterCannotVerifySchedule11() throws Exception {
    mockMvc
        .perform(reversal(VERIFY_11, SCH11_DRAFT_MILL).with(canonicalSubmitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));
    mockMvc.perform(post(VERIFY_11).with(canonicalSubmitter())).andExpect(status().isForbidden());

    assertThat(silvicultureStatus(SCH11_DRAFT_MILL)).isEqualTo("D");
  }

  @Test
  @DisplayName("26.3 AC 6: an unauthenticated caller is denied Schedule 11 Verify")
  void anonymousCannotVerifySchedule11() throws Exception {
    mockMvc.perform(reversal(VERIFY_11, SCH11_DRAFT_MILL)).andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("26.3 AC 6: an ADMIN reaches the Schedule 11 transition — proven by its 409")
  void adminReachesTheSchedule11Verify() throws Exception {
    // The negative control for the two arms above: 810 is already Verified, so the ADMIN gets
    // past authorization and the context guard and is stopped by the status rule, writing nothing.
    mockMvc
        .perform(
            reversal(VERIFY_11, SCH11_VERIFIED_MILL).with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(SUBMISSION_ERROR)));

    assertThat(silvicultureStatus(SCH11_VERIFIED_MILL)).isEqualTo("V");
  }

  // --- The two Schedule 11 reversals sit behind the same action
  // ----------------------------------

  private static final String SET_TO_DRAFT_11 = "/api/v1/check-status/schedule11/set-to-draft";
  private static final String SET_TO_SUBMIT_11 = "/api/v1/check-status/schedule11/set-to-submit";

  /** R__62's silviculture-Draft refused-arm mill: written by nothing in any suite. */
  private static final String SCH11_REVERSAL_DRAFT_MILL = "827";

  @Test
  @DisplayName(
      "a Licensee is denied both Schedule 11 reversals — 403 before parameters, nothing written")
  void submitterCannotReverseSchedule11() throws Exception {
    for (String endpoint : List.of(SET_TO_DRAFT_11, SET_TO_SUBMIT_11)) {
      mockMvc
          .perform(reversal(endpoint, SCH11_REVERSAL_DRAFT_MILL).with(canonicalSubmitter()))
          .andExpect(status().isForbidden())
          .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));
      mockMvc.perform(post(endpoint).with(canonicalSubmitter())).andExpect(status().isForbidden());
    }

    assertThat(silvicultureStatus(SCH11_REVERSAL_DRAFT_MILL)).isEqualTo("D");
  }

  @Test
  @DisplayName("an unauthenticated caller is denied both Schedule 11 reversals")
  void anonymousCannotReverseSchedule11() throws Exception {
    mockMvc
        .perform(reversal(SET_TO_DRAFT_11, SCH11_REVERSAL_DRAFT_MILL))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(reversal(SET_TO_SUBMIT_11, SCH11_REVERSAL_DRAFT_MILL))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("an ADMIN reaches both Schedule 11 reversals — proven by their 409s")
  void adminReachesTheSchedule11Reversals() throws Exception {
    // The negative control: 827's silviculture track is at Draft, so both reversals get past
    // authorization and the context guard and are stopped by the status rule, writing nothing.
    for (String endpoint : List.of(SET_TO_DRAFT_11, SET_TO_SUBMIT_11)) {
      mockMvc
          .perform(
              reversal(endpoint, SCH11_REVERSAL_DRAFT_MILL)
                  .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
          .andExpect(status().isConflict())
          .andExpect(jsonPath("$.detail", is(SUBMISSION_ERROR)));
    }

    assertThat(silvicultureStatus(SCH11_REVERSAL_DRAFT_MILL)).isEqualTo("D");
  }
}
