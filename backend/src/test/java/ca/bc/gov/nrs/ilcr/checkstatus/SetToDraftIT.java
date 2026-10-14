package ca.bc.gov.nrs.ilcr.checkstatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test — {@code POST /api/v1/check-status/set-to-draft}, the Submitted&rarr;Draft
 * reversal that hands a report back to the Licensee for rework (UC-CHK-016, FR5, Story 18.1).
 *
 * <p>Security ON, and here that is a choice rather than a necessity. This transition records no
 * identity pair, so unlike {@code VerifyReportIT} it has no auditor arm that needs a directory GUID
 * — but the token is what makes AC 3's <em>negative</em> assertion meaningful. The acting admin
 * carries a GUID and IS associated to every fixture mill, so a wrong SET list would have a real
 * cross-reference row to write; the columns staying at their seeded values is therefore evidence
 * that nothing was written, not evidence that nothing was available to write.
 *
 * <p>Every failure arm asserts the {@code (status, detail)} pair, never the status alone: three
 * distinct 409s share this endpoint (the gate, the legality guard and the closed mill) and a bare
 * {@code isConflict()} cannot tell them apart.
 *
 * <p>Mills are this class's own ({@code R__56}). Only 790 is mutated, by one test. 792/793/794/796
 * are refused arms and are never written at all — which is itself asserted, by fingerprint.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("POST /api/v1/check-status/set-to-draft — the S->D reversal (Story 18.1)")
class SetToDraftIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/check-status/set-to-draft";
  private static final String PROBLEM_JSON = "application/problem+json";
  private static final String YEAR = "2021";

  private static final String HAPPY_MILL = "790";
  private static final String GATE_FAILS_MILL = "792";
  private static final String DRAFT_MILL = "793";
  private static final String VERIFIED_MILL = "794";
  private static final String CLOSED_MILL = "796";

  /** The seeded identity pairs neither reversal may touch (AC 3). */
  private static final String SEEDED_LICENSEE_GUID = "REVERSALLICENSEE1111222233334444";

  private static final String SEEDED_AUDITOR_GUID = "REVERSALAUDITOR11111222233334444";

  private static final String ACTING_USER = "reversaladmin";

  /** The acting admin's own directory GUID — associated to every R__56 mill. */
  private static final String ADMIN_GUID = "REVERSALAUDITOR11111222233334444";

  /**
   * Deliberately different from {@link #ACTING_USER} and deliberately the 36-char Cognito UUID
   * shape that would overflow {@code UPDATE_USERID VARCHAR2(30)}, so stamping the subject instead
   * of {@code custom:idp_username} fails loudly rather than silently agreeing.
   */
  private static final String COGNITO_SUB = "99999999-8888-7777-6666-555555555555";

  private static final String SEED_USER = "SEED";

  private static final String DRAFT_MSG = "Schedules 1-10 have been set back to draft.";

  /**
   * Deviation (V), BA-ratified 2026-09-21. Legacy answered a failing gate on THIS button with the
   * submit text — "The report cannot be submitted. One or more of the Schedules have not passed
   * validation. Please review and correct any errors." — which names neither the action the admin
   * took nor the remedy. The gate is unchanged; only the sentence is.
   */
  private static final String GATE_FAILED_MSG =
      "Schedules 1-10 cannot be set to Draft while one or more Schedules have errors."
          + " Please correct them and try again.";

  /** Legacy's text, which this endpoint must NOT return any more. */
  private static final String LEGACY_SUBMIT_GATE_MSG =
      "The report cannot be submitted. One or more of the Schedules have not passed validation."
          + " Please review and correct any errors.";

  private static final String NOT_SUBMITTED_STATUS_MSG =
      "Schedules 1-10 are no longer in Submitted and cannot be set to Draft.";

  /** ERR-001, byte-for-byte from legacy — the trailing space is real. */
  private static final String ERR_001 = "Please Select Mill and Reporting Year in the Home Page. ";

  private static final String ERR_002 =
      "This Mill is not active for the current Reporting Year. "
          + "Please select another mill from the Home Page.";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;
  @Autowired private JdbcTemplate jdbcTemplate;

  /**
   * Built through the PRODUCTION converter rather than {@code spring-security-test}'s bare {@code
   * jwt()}, which constructs its own token and never calls {@link FamJwtAuthenticationConverter} —
   * so the principal name would fall back to {@code sub} and the audit-stamp assertions would pass
   * whichever claim the app actually read.
   */
  private RequestPostProcessor admin() {
    Jwt token =
        Jwt.withTokenValue("set-to-draft-it-token")
            .header("alg", "none")
            .subject(COGNITO_SUB)
            .claim("idir_user_guid", ADMIN_GUID)
            .claim("idir_username", ACTING_USER)
            .claim("identity_provider", "azureidir")
            .claim("client_roles", List.of("ILCR_ADMIN"))
            .build();
    return authentication(CONVERTER.convert(token));
  }

  private String scalar(String column, String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT "
            + column
            + " FROM THE.ILCR_MILL_REPORT_STATUS"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
        Integer.valueOf(mill));
  }

  private String trackStatus(String mill) {
    return scalar("ILCR_MILL_REPORT_STATUS_CODE", mill);
  }

  private String silvicultureStatus(String mill) {
    return scalar("MILL_SILVICULTUR_STATUS_CODE", mill);
  }

  private Long identityMillId(String column, String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT "
            + column
            + " FROM THE.ILCR_MILL_REPORT_STATUS"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        Long.class,
        Integer.valueOf(mill));
  }

  private List<String> categoryStates(String mill) {
    return jdbcTemplate.queryForList(
        "SELECT CATEGORY_STATE_CODE FROM THE.ILCR_REPORT_CATEGORY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021"
            + " AND ILCR_CATEGORY_ID IN ('1','2','3','4','5','6','7','8','9','10')"
            + " ORDER BY TO_NUMBER(ILCR_CATEGORY_ID)",
        String.class,
        Integer.valueOf(mill));
  }

  private String categoryState(String mill, String categoryId) {
    return jdbcTemplate.queryForObject(
        "SELECT CATEGORY_STATE_CODE FROM THE.ILCR_REPORT_CATEGORY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021 AND ILCR_CATEGORY_ID = ?",
        String.class,
        Integer.valueOf(mill),
        categoryId);
  }

  private String categoryUpdateUser(String mill, String categoryId) {
    return jdbcTemplate.queryForObject(
        "SELECT UPDATE_USERID FROM THE.ILCR_REPORT_CATEGORY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021 AND ILCR_CATEGORY_ID = ?",
        String.class,
        Integer.valueOf(mill),
        categoryId);
  }

  private int rowCount(String table, String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE." + table + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        Integer.class,
        Integer.valueOf(mill));
  }

  /** Rows the acting user did NOT stamp — a COUNT, so one stamped row cannot satisfy it. */
  private int unstampedRows(String table, String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE."
            + table
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021"
            + " AND (UPDATE_USERID IS NULL OR UPDATE_USERID <> ?)",
        Integer.class,
        Integer.valueOf(mill),
        ACTING_USER);
  }

  private int unstampedCategoryRows(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE.ILCR_REPORT_CATEGORY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021"
            + " AND ILCR_CATEGORY_ID IN ('1','2','3','4','5','6','7','8','9','10')"
            + " AND (UPDATE_USERID IS NULL OR UPDATE_USERID <> ?)",
        Integer.class,
        Integer.valueOf(mill),
        ACTING_USER);
  }

  private int summaryCostDetailCount(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE.ILCR_COST_REPORT_DETAIL d"
            + " WHERE d.ILCR_REPORT_SUMMARY_ID IN ("
            + "   SELECT s.ILCR_REPORT_SUMMARY_ID FROM THE.ILCR_REPORT_SUMMARY s"
            + "    WHERE s.ILCR_MILL_ID = ? AND s.REPORT_YEAR = 2021)",
        Integer.class,
        Integer.valueOf(mill));
  }

  private int unstampedSummaryCostDetails(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE.ILCR_COST_REPORT_DETAIL d"
            + " WHERE d.ILCR_REPORT_SUMMARY_ID IN ("
            + "   SELECT s.ILCR_REPORT_SUMMARY_ID FROM THE.ILCR_REPORT_SUMMARY s"
            + "    WHERE s.ILCR_MILL_ID = ? AND s.REPORT_YEAR = 2021)"
            + " AND (d.UPDATE_USERID IS NULL OR d.UPDATE_USERID <> ?)",
        Integer.class,
        Integer.valueOf(mill),
        ACTING_USER);
  }

  private int statusRevision(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT REVISION_COUNT FROM THE.ILCR_MILL_REPORT_STATUS"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        Integer.class,
        Integer.valueOf(mill));
  }

  /** MIN, so one un-bumped row fails rather than being averaged away. */
  private int minSummaryRevision(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT MIN(REVISION_COUNT) FROM THE.ILCR_REPORT_SUMMARY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        Integer.class,
        Integer.valueOf(mill));
  }

  /**
   * MIN over categories {@code '1'}–{@code '10'} ONLY, as {@code VerifyReportIT} does. Category
   * {@code '11'} is Schedule 11's and must never advance (AC 11), so it keeps revision 0 for ever;
   * include it and the MIN can never move and the assertion below tests nothing. A shared {@code
   * minRevision(table, mill)} helper did include it, which is how that happened.
   */
  private int minCategoryRevision(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT MIN(REVISION_COUNT) FROM THE.ILCR_REPORT_CATEGORY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021"
            + " AND ILCR_CATEGORY_ID IN ('1','2','3','4','5','6','7','8','9','10')",
        Integer.class,
        Integer.valueOf(mill));
  }

  private int auditRowCount(String auditTable) {
    return jdbcTemplate.queryForObject("SELECT COUNT(*) FROM THE." + auditTable, Integer.class);
  }

  /**
   * Everything this mill's data can show about a refused reversal: the status row including BOTH
   * identity pairs, every one of the eleven category rows with its actor, the summaries' actors,
   * and the count of stamped cost details. The Schedule 4&ndash;10 families are not read because
   * these mills carry no rows in them, so a stray stamp there would affect zero rows regardless;
   * the cost-detail count is sufficient because the seed leaves {@code UPDATE_USERID} NULL, so the
   * first stamp on any row changes it.
   *
   * <p>Row counts alone cannot catch a stray audit stamp inside a refused request — a stamp changes
   * no count — so this reads the audit columns themselves. Carried over from {@code VerifyReportIT}
   * with the LICENSEE pair added, because a wrong SET list on this endpoint would write that pair,
   * not the auditor one.
   */
  private String fingerprint(String mill) {
    StringBuilder print = new StringBuilder();
    print
        .append("STATUS=")
        .append(
            jdbcTemplate.queryForObject(
                "SELECT NVL(ILCR_MILL_REPORT_STATUS_CODE,'-')"
                    + " || '/' || NVL(MILL_SILVICULTUR_STATUS_CODE,'-')"
                    + " || '/r' || NVL(TO_CHAR(REVISION_COUNT),'-')"
                    + " || '/' || NVL(TO_CHAR(LICENSEE_MILL_ID),'-')"
                    + " || '/' || NVL(LICENSEE_USER_GUID,'-')"
                    + " || '/' || NVL(TO_CHAR(AUDITOR_MILL_ID),'-')"
                    + " || '/' || NVL(AUDITOR_USER_GUID,'-')"
                    + " || '/' || NVL(UPDATE_USERID,'-')"
                    + " FROM THE.ILCR_MILL_REPORT_STATUS"
                    + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
                String.class,
                Integer.valueOf(mill)))
        .append(';');
    print
        .append("CATEGORIES=")
        .append(
            jdbcTemplate.queryForList(
                "SELECT ILCR_CATEGORY_ID || '=' || NVL(CATEGORY_STATE_CODE,'-')"
                    + " || '/' || NVL(UPDATE_USERID,'-')"
                    + " FROM THE.ILCR_REPORT_CATEGORY"
                    + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021"
                    + " ORDER BY TO_NUMBER(ILCR_CATEGORY_ID)",
                String.class,
                Integer.valueOf(mill)))
        .append(';');
    print
        .append("SUMMARIES=")
        .append(
            jdbcTemplate.queryForList(
                "SELECT s.ILCR_CATEGORY_ID || '/' || NVL(s.UPDATE_USERID,'-')"
                    + " FROM THE.ILCR_REPORT_SUMMARY s"
                    + " WHERE s.ILCR_MILL_ID = ? AND s.REPORT_YEAR = 2021"
                    + " ORDER BY s.ILCR_REPORT_SUMMARY_ID",
                String.class,
                Integer.valueOf(mill)))
        .append(';');
    print
        .append("COST_DETAIL_STAMPS=")
        .append(
            jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM THE.ILCR_COST_REPORT_DETAIL d"
                    + " WHERE d.ILCR_REPORT_SUMMARY_ID IN ("
                    + "   SELECT s.ILCR_REPORT_SUMMARY_ID FROM THE.ILCR_REPORT_SUMMARY s"
                    + "    WHERE s.ILCR_MILL_ID = ? AND s.REPORT_YEAR = 2021)"
                    + " AND d.UPDATE_USERID IS NOT NULL",
                Integer.class,
                Integer.valueOf(mill)));
    return print.toString();
  }

  @Test
  @DisplayName(
      "AC1/AC3/AC4/AC11: all-met Submitted track -> 200, S->D, ten categories -> D,"
          + " neither identity pair written")
  void setsASubmittedTrackBackToDraft() throws Exception {
    assertThat(trackStatus(HAPPY_MILL)).isEqualTo("S");
    assertThat(categoryStates(HAPPY_MILL)).hasSize(10).containsOnly("A");
    int statusRevisionBefore = statusRevision(HAPPY_MILL);
    int summaryRevisionBefore = minSummaryRevision(HAPPY_MILL);
    int categoryRevisionBefore = minCategoryRevision(HAPPY_MILL);
    int summaryAuditBefore = auditRowCount("ILCR_REPORT_SUMMARY_AUDIT");
    int costDetailAuditBefore = auditRowCount("ILCR_COST_REPORT_DETAIL_AUD");

    mockMvc
        .perform(post(ENDPOINT).param("millId", HAPPY_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trackStatus", is("D")))
        .andExpect(jsonPath("$.message.key", is("sch1-10DraftMsg")))
        // D4: before this story the key was absent from messages.properties and the fallback
        // resolved it to itself, so this endpoint would have answered 200 with the literal
        // "sch1-10DraftMsg" as its text. Asserting the TEXT is what catches that.
        .andExpect(jsonPath("$.message.text", is(DRAFT_MSG)));

    // Named phases rather than one 25-assertion block. The reversal MUTATES this mill, so these
    // cannot be separate @Test methods — a second POST would answer 409.
    assertTransitionApplied();
    assertNeitherIdentityPairWritten();
    assertEveryRowStamped();
    assertRevisionsFollowLegacy(
        statusRevisionBefore, summaryRevisionBefore, categoryRevisionBefore);
    assertNoAuditRowsInserted(summaryAuditBefore, costDetailAuditBefore);
    assertEditabilityFlipped();
  }

  /**
   * AC 12 (CHK-016 BR-05): after S&rarr;D the assigned Licensee edits and the ministry does not.
   * This falls out of Story 16.1's matrix ({@code ScheduleEditability.java:63-64} — SUBMITTER at
   * {@code D}, ADMIN at {@code S}/{@code V}) and no matrix row was added; the consequence is what
   * is asserted. The 18.1 code review found the Completion Notes claimed this arm and no test had
   * it — the only AC with zero coverage.
   */
  private void assertEditabilityFlipped() throws Exception {
    mockMvc
        .perform(
            get("/api/v1/schedule1")
                .param("millId", HAPPY_MILL)
                .param("year", YEAR)
                .with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.editable", is(true)));
    mockMvc
        .perform(
            get("/api/v1/schedule1").param("millId", HAPPY_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.editable", is(false)));
  }

  /** AC1/AC11: the track moved, the ten categories with it, Schedule 11 did not. */
  private void assertTransitionApplied() {
    assertThat(trackStatus(HAPPY_MILL)).isEqualTo("D");
    assertThat(categoryStates(HAPPY_MILL)).hasSize(10).containsOnly("D");

    // BR-07 track independence, asserted by value against a DIFFERENT seeded code so a write that
    // reached MILL_SILVICULTUR_STATUS_CODE fails here instead of coinciding with the right answer.
    assertThat(silvicultureStatus(HAPPY_MILL)).isEqualTo("V");
    assertThat(categoryState(HAPPY_MILL, "11")).isEqualTo("S");
    assertThat(categoryUpdateUser(HAPPY_MILL, "11")).isEqualTo(SEED_USER);
    // AC 11's third arm: the Schedule 11 data row itself, by value. R__56 seeds one per happy mill
    // precisely so this is not vacuous; the twenty audit statements name no Schedule 11 table.
    assertThat(silvicultureRow(HAPPY_MILL)).isEqualTo("Reversal Block 790/-/r0");
  }

  /**
   * The seeded {@code BASIC_SILVICULTURE_REPORT} row, as one string: location / actor / revision.
   */
  private String silvicultureRow(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT LOCATION || '/' || NVL(UPDATE_USERID,'-') || '/r' || TO_CHAR(REVISION_COUNT)"
            + " FROM THE.BASIC_SILVICULTURE_REPORT WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
        Integer.valueOf(mill));
  }

  /**
   * AC3, the assertion this story exists to make. Legacy skipped the whole association block for a
   * {@code 'D'} target ({@code SubmitReportDAO:401}), so both pairs survive the reversal exactly as
   * the submit and verify before it left them.
   *
   * <p>By VALUE, not merely non-null: the acting admin IS associated to this mill, so routing this
   * transition through {@code updateTrackStatusWithAuditor} would have written a real, non-null
   * auditor pair and a "not null" assertion would have passed.
   */
  private void assertNeitherIdentityPairWritten() {
    assertThat(scalar("LICENSEE_USER_GUID", HAPPY_MILL)).isEqualTo(SEEDED_LICENSEE_GUID);
    assertThat(identityMillId("LICENSEE_MILL_ID", HAPPY_MILL)).isEqualTo(790L);
    assertThat(scalar("AUDITOR_USER_GUID", HAPPY_MILL)).isEqualTo(SEEDED_AUDITOR_GUID);
    assertThat(identityMillId("AUDITOR_MILL_ID", HAPPY_MILL)).isEqualTo(790L);
  }

  /** AC1: every row stamped, each assertion paired with its count so an empty table cannot pass. */
  private void assertEveryRowStamped() {
    assertThat(rowCount("ILCR_MILL_REPORT_STATUS", HAPPY_MILL)).isOne();
    assertThat(unstampedRows("ILCR_MILL_REPORT_STATUS", HAPPY_MILL)).isZero();

    assertThat(rowCount("ILCR_REPORT_SUMMARY", HAPPY_MILL)).isPositive();
    assertThat(unstampedRows("ILCR_REPORT_SUMMARY", HAPPY_MILL)).isZero();

    assertThat(summaryCostDetailCount(HAPPY_MILL)).isPositive();
    assertThat(unstampedSummaryCostDetails(HAPPY_MILL)).isZero();

    assertThat(unstampedCategoryRows(HAPPY_MILL)).isZero();
  }

  /**
   * {@code REVISION_COUNT} follows legacy entity by entity, and the reversal statement differs from
   * submit's here: {@code updateTrackStatusWithoutIdentity} does NOT bump the status row, matching
   * {@code updateTrackStatusWithAuditor} and legacy (a plain column, never a {@code @Version}).
   * {@code ILCR_REPORT_SUMMARY} and {@code ILCR_REPORT_CATEGORY} ARE bumped — both declared
   * {@code @Version} in legacy, so Hibernate incremented them when the sweep dirtied them.
   */
  private void assertRevisionsFollowLegacy(
      int statusBefore, int summaryBefore, int categoryBefore) {
    assertThat(statusRevision(HAPPY_MILL)).isEqualTo(statusBefore);
    assertThat(minSummaryRevision(HAPPY_MILL)).isEqualTo(summaryBefore + 1);
    assertThat(minCategoryRevision(HAPPY_MILL)).isEqualTo(categoryBefore + 1);
  }

  /**
   * The application inserts no {@code _AUD} row — delivery triggers own those, and the test
   * snapshot creates the shadow tables without them ({@code V20260910}), so this is provable here.
   */
  private void assertNoAuditRowsInserted(int summaryAuditBefore, int costDetailAuditBefore) {
    assertThat(auditRowCount("ILCR_REPORT_SUMMARY_AUDIT")).isEqualTo(summaryAuditBefore);
    assertThat(auditRowCount("ILCR_COST_REPORT_DETAIL_AUD")).isEqualTo(costDetailAuditBefore);
  }

  @Test
  @DisplayName(
      "AC5/AC10 + deviation (V): a failing validation gate -> 409 naming THIS action,"
          + " nothing persisted")
  void refusesWhenTheGateFails() throws Exception {
    // D5, as the BA ruled it 2026-09-21. The GATE stays: a Submitted report can only acquire
    // errors because a ministry user introduced them, and that user has ADMIN edit rights at
    // Submitted (ScheduleEditability:63-64), so they correct the errors in place and retry —
    // nothing is stranded. What changed is the sentence: legacy answered this button with the
    // SUBMIT text, telling an admin who had clicked Set to Draft that their submission failed.
    String before = fingerprint(GATE_FAILS_MILL);

    mockMvc
        .perform(post(ENDPOINT).param("millId", GATE_FAILS_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        .andExpect(jsonPath("$.detail", is(GATE_FAILED_MSG)))
        // The behaviour is unchanged, so the only way to prove the wording moved is to assert the
        // old text is gone. Without this the arm passes against either message.
        .andExpect(jsonPath("$.detail", not(is(LEGACY_SUBMIT_GATE_MSG))));

    assertThat(trackStatus(GATE_FAILS_MILL)).isEqualTo("S");
    assertThat(fingerprint(GATE_FAILS_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC7/AC10: the D->D no-op -> 409 setToDraftNotSubmittedErrorMsg, nothing persisted")
  void refusesANoOp() throws Exception {
    String before = fingerprint(DRAFT_MILL);

    mockMvc
        .perform(post(ENDPOINT).param("millId", DRAFT_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        // D3: the transition's OWN text, not 17.1's generic "contact ILCR application support".
        // Deviation (T) — an admin who double-clicked has done nothing wrong.
        .andExpect(jsonPath("$.detail", is(NOT_SUBMITTED_STATUS_MSG)));

    assertThat(trackStatus(DRAFT_MILL)).isEqualTo("D");
    assertThat(fingerprint(DRAFT_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC7/AC10: a Verified track -> 409 (the illegal V->D jump), nothing persisted")
  void refusesTheVerifiedToDraftJump() throws Exception {
    // Legacy rejected this pair explicitly (isMillReportStatusValid:456-458) AND its category map
    // never named "VD", so it could not have completed either way.
    String before = fingerprint(VERIFIED_MILL);

    mockMvc
        .perform(post(ENDPOINT).param("millId", VERIFIED_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(NOT_SUBMITTED_STATUS_MSG)));

    assertThat(trackStatus(VERIFIED_MILL)).isEqualTo("V");
    assertThat(fingerprint(VERIFIED_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC8: a closed mill -> 409 ERR-002, refused before any schedule is read")
  void refusesAClosedMill() throws Exception {
    String before = fingerprint(CLOSED_MILL);

    mockMvc
        .perform(post(ENDPOINT).param("millId", CLOSED_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(ERR_002)));

    assertThat(trackStatus(CLOSED_MILL)).isEqualTo("S");
    assertThat(fingerprint(CLOSED_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC8: missing millId -> 400 ERR-001 verbatim, trailing space included")
  void refusesAMissingMillId() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("year", YEAR).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
  }

  @Test
  @DisplayName("AC8: non-numeric millId -> 400 ERR-001, never Spring's generic 400")
  void refusesANonNumericMillId() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("millId", "not-a-mill").param("year", YEAR).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
  }

  @Test
  @DisplayName("AC8: a blank millId -> 400 ERR-001 — blank is not the same path as absent")
  void refusesABlankMillId() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("millId", "  ").param("year", YEAR).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
  }

  @Test
  @DisplayName("AC8: missing, blank and non-numeric year all -> 400 ERR-001")
  void refusesABadYear() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("millId", DRAFT_MILL).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
    mockMvc
        .perform(post(ENDPOINT).param("millId", DRAFT_MILL).param("year", "  ").with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
    mockMvc
        .perform(post(ENDPOINT).param("millId", DRAFT_MILL).param("year", "twenty21").with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
  }

  @Test
  @DisplayName("AC8: an unknown mill -> 404 with the Check Status page's own not-found text")
  void refusesAnUnknownMill() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("millId", "999999").param("year", YEAR).with(admin()))
        .andExpect(status().isNotFound())
        .andExpect(
            jsonPath(
                "$.detail",
                is("One or more of the schedules for the report have not been found.")));
  }
}
