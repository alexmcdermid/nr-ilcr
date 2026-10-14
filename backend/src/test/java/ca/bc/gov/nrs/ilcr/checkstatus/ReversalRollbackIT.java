package ca.bc.gov.nrs.ilcr.checkstatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test — both reversals are atomic across all fifteen tables (AC 10). A mid-sweep
 * failure is forced by spying the repository, because no fixture can provoke one: every statement
 * is valid SQL against a seeded schema.
 *
 * <p>The failure is forced at the CATEGORY ADVANCE, which is the last of the three steps, so by the
 * time it throws the status write and all twenty audit statements have already succeeded inside the
 * transaction. That is what makes this arm prove the boundary rather than just the status write: if
 * {@code @Transactional} sat anywhere but on {@link ReportTransitionWriter#writeReversal}, the
 * report would be left Draft-but-uncategorised, or stamped by a reversal that never happened — a
 * half-transitioned report no screen could explain.
 *
 * <p>Its own mills (795, 798) and its own class: a spy that throws is context-wide, and a
 * half-applied transition would poison any fixture shared with another arm. Both mills are chosen
 * all-met so the forced failure is reached after every guard has passed.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Check Status reversals — rollback on a mid-sweep failure (Story 18.1)")
class ReversalRollbackIT extends AbstractOracleIT {

  private static final String SET_TO_DRAFT = "/api/v1/check-status/set-to-draft";
  private static final String SET_TO_SUBMIT = "/api/v1/check-status/set-to-submit";
  private static final String YEAR = "2021";

  /** All-met and Submitted — the Set to Draft rollback arm. */
  private static final String DRAFT_ROLLBACK_MILL = "798";

  /** All-met and Verified — the Set to Submit rollback arm. */
  private static final String SUBMIT_ROLLBACK_MILL = "795";

  private static final String ACTING_USER = "reversaladmin";
  private static final String ADMIN_GUID = "REVERSALAUDITOR11111222233334444";
  private static final String SUBMISSION_ERROR_MSG =
      "An error has been found submitting schedules. The error details have been logged."
          + " Please contact ILCR application support.";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;
  @Autowired private JdbcTemplate jdbcTemplate;
  @MockitoSpyBean private ReportTrackTransitionRepository repository;

  /**
   * Built through the PRODUCTION converter, as {@code SetToDraftIT} does and for the reason it
   * gives: {@code spring-security-test}'s bare {@code jwt()} never calls {@link
   * FamJwtAuthenticationConverter}, so the principal name falls back to {@code sub}. This class
   * first used that shortcut with {@code sub = ACTING_USER}, which made its stamped-row filter pass
   * whichever claim the app read; the 18.1 code review pointed out the class beside it documents
   * exactly that trap.
   */
  private RequestPostProcessor admin() {
    Jwt token =
        Jwt.withTokenValue("reversal-rollback-it-token")
            .header("alg", "none")
            .subject("99999999-8888-7777-6666-555555555555")
            .claim("idir_user_guid", ADMIN_GUID)
            .claim("idir_username", ACTING_USER)
            .claim("identity_provider", "azureidir")
            .claim("client_roles", List.of("ILCR_ADMIN"))
            .build();
    return authentication(CONVERTER.convert(token));
  }

  private String trackStatus(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT ILCR_MILL_REPORT_STATUS_CODE FROM THE.ILCR_MILL_REPORT_STATUS"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
        Integer.valueOf(mill));
  }

  private List<String> categoryStates(String mill) {
    return jdbcTemplate.queryForList(
        "SELECT CATEGORY_STATE_CODE FROM THE.ILCR_REPORT_CATEGORY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021"
            + " AND ILCR_CATEGORY_ID IN ('1','2','3','4','5','6','7','8','9','10')",
        String.class,
        Integer.valueOf(mill));
  }

  /**
   * Rows this mill's reversal would have stamped. Zero before and after a rolled-back request: the
   * audit sweep runs BEFORE the category advance that fails, so a leaked stamp is exactly what a
   * broken transaction boundary would leave behind.
   */
  private int stampedRows(String mill) {
    Integer summaries =
        jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM THE.ILCR_REPORT_SUMMARY"
                + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021 AND UPDATE_USERID = ?",
            Integer.class,
            Integer.valueOf(mill),
            ACTING_USER);
    Integer costDetails =
        jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM THE.ILCR_COST_REPORT_DETAIL d"
                + " WHERE d.ILCR_REPORT_SUMMARY_ID IN ("
                + "   SELECT s.ILCR_REPORT_SUMMARY_ID FROM THE.ILCR_REPORT_SUMMARY s"
                + "    WHERE s.ILCR_MILL_ID = ? AND s.REPORT_YEAR = 2021)"
                + " AND d.UPDATE_USERID = ?",
            Integer.class,
            Integer.valueOf(mill),
            ACTING_USER);
    Integer statusRow =
        jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM THE.ILCR_MILL_REPORT_STATUS"
                + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021 AND UPDATE_USERID = ?",
            Integer.class,
            Integer.valueOf(mill),
            ACTING_USER);
    return summaries + costDetails + statusRow;
  }

  @Test
  @DisplayName("AC10: a failure after the status write rolls the whole Set to Draft back")
  void rollsBackSetToDraft() throws Exception {
    assertThat(trackStatus(DRAFT_ROLLBACK_MILL)).isEqualTo("S");
    assertThat(categoryStates(DRAFT_ROLLBACK_MILL)).containsOnly("A");
    assertThat(stampedRows(DRAFT_ROLLBACK_MILL)).isZero();

    doThrow(new DataIntegrityViolationException("forced mid-sweep failure"))
        .when(repository)
        .advanceCategoryState(anyLong(), anyInt(), anyString(), anyString(), anyString());

    mockMvc
        .perform(
            post(SET_TO_DRAFT)
                .param("millId", DRAFT_ROLLBACK_MILL)
                .param("year", YEAR)
                .with(admin()))
        .andExpect(status().isInternalServerError())
        .andExpect(jsonPath("$.detail", is(SUBMISSION_ERROR_MSG)));

    // The status write and all twenty audit statements had already succeeded inside the
    // transaction; the rollback undoes every one of them. AC10: a 200 means committed, so a
    // persistence failure must never reach the caller as one.
    assertThat(trackStatus(DRAFT_ROLLBACK_MILL)).isEqualTo("S");
    assertThat(categoryStates(DRAFT_ROLLBACK_MILL)).containsOnly("A");
    assertThat(stampedRows(DRAFT_ROLLBACK_MILL)).isZero();
  }

  @Test
  @DisplayName("AC10: a failure after the status write rolls the whole Set to Submit back")
  void rollsBackSetToSubmit() throws Exception {
    assertThat(trackStatus(SUBMIT_ROLLBACK_MILL)).isEqualTo("V");
    assertThat(categoryStates(SUBMIT_ROLLBACK_MILL)).containsOnly("V");
    assertThat(stampedRows(SUBMIT_ROLLBACK_MILL)).isZero();

    doThrow(new DataIntegrityViolationException("forced mid-sweep failure"))
        .when(repository)
        .advanceCategoryState(anyLong(), anyInt(), anyString(), anyString(), anyString());

    mockMvc
        .perform(
            post(SET_TO_SUBMIT)
                .param("millId", SUBMIT_ROLLBACK_MILL)
                .param("year", YEAR)
                .with(admin()))
        .andExpect(status().isInternalServerError())
        .andExpect(jsonPath("$.detail", is(SUBMISSION_ERROR_MSG)));

    assertThat(trackStatus(SUBMIT_ROLLBACK_MILL)).isEqualTo("V");
    assertThat(categoryStates(SUBMIT_ROLLBACK_MILL)).containsOnly("V");
    assertThat(stampedRows(SUBMIT_ROLLBACK_MILL)).isZero();
  }
}
