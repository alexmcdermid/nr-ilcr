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
 * Acceptance test — {@code POST /api/v1/check-status/set-to-submit}, the Verified&rarr;Submitted
 * reversal that withdraws a verification so the report can be re-reviewed (UC-CHK-018, FR5, Story
 * 18.1).
 *
 * <p><strong>AC 3 carries more weight on this endpoint than on its sibling.</strong> For Set to
 * Draft, writing no identity pair is exact legacy parity. Here it is recorded deviation (S): legacy
 * targeted {@code 'S'} and so wrote the LICENSEE pair from the ACTING ADMIN's cross-reference
 * ({@code SubmitReportDAO:406-407}), overwriting the record of who actually submitted — and writing
 * NULL whenever that admin has no assignment for the mill, the normal case for a ministry user. The
 * acting admin here IS associated to every fixture mill precisely so the "unchanged by value"
 * assertion has something to fail against: under legacy's SET list this mill's {@code LICENSEE_*}
 * pair would be rewritten to the admin's, not merely nulled.
 *
 * <p>Every failure arm asserts the {@code (status, detail)} pair — three distinct 409s share this
 * endpoint.
 *
 * <p>Mills are this class's own ({@code R__56}). Only 791 is mutated, by one test; 792/793/797/796
 * are refused arms and are asserted unchanged by fingerprint. 793 is deliberately at Draft: {@code
 * D}&rarr;{@code S} IS a legal pair, but it is the licensee's SUBMIT and must not be reachable
 * through this endpoint.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("POST /api/v1/check-status/set-to-submit — the V->S reversal (Story 18.1)")
class SetToSubmitIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/check-status/set-to-submit";
  private static final String PROBLEM_JSON = "application/problem+json";
  private static final String YEAR = "2021";

  private static final String HAPPY_MILL = "791";
  private static final String GATE_FAILS_MILL = "792";
  private static final String DRAFT_MILL = "793";
  private static final String SUBMITTED_MILL = "797";
  private static final String CLOSED_MILL = "796";

  private static final String SEEDED_LICENSEE_GUID = "REVERSALLICENSEE1111222233334444";
  private static final String SEEDED_AUDITOR_GUID = "REVERSALAUDITOR11111222233334444";

  private static final String ACTING_USER = "reversaladmin";
  private static final String ADMIN_GUID = "REVERSALAUDITOR11111222233334444";
  private static final String COGNITO_SUB = "99999999-8888-7777-6666-555555555555";
  private static final String SEED_USER = "SEED";

  /** Legacy reused the submit text — there is no "verification reversed" message to port. */
  private static final String SUBMITTED_MSG = "Schedules 1-10 are successfully submitted.";

  /** Deviation (V) — see {@code SetToDraftIT}. The gate is unchanged; only the sentence is. */
  private static final String GATE_FAILED_MSG =
      "Schedules 1-10 cannot be set to Submit while one or more Schedules have errors."
          + " Please correct them and try again.";

  /** Legacy's text, which this endpoint must NOT return any more. */
  private static final String LEGACY_SUBMIT_GATE_MSG =
      "The report cannot be submitted. One or more of the Schedules have not passed validation."
          + " Please review and correct any errors.";

  private static final String NOT_VERIFIED_STATUS_MSG =
      "Schedules 1-10 are no longer in Verified and cannot be set to Submit.";

  /** ERR-001, byte-for-byte from legacy — the trailing space is real. */
  private static final String ERR_001 = "Please Select Mill and Reporting Year in the Home Page. ";

  private static final String ERR_002 =
      "This Mill is not active for the current Reporting Year. "
          + "Please select another mill from the Home Page.";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;
  @Autowired private JdbcTemplate jdbcTemplate;

  private RequestPostProcessor admin() {
    Jwt token =
        Jwt.withTokenValue("set-to-submit-it-token")
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
   * Categories {@code '1'}–{@code '10'} only — {@code '11'} never advances and would pin the MIN.
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
   * The seeded {@code BASIC_SILVICULTURE_REPORT} row, as one string: location / actor / revision.
   */
  private String silvicultureRow(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT LOCATION || '/' || NVL(UPDATE_USERID,'-') || '/r' || TO_CHAR(REVISION_COUNT)"
            + " FROM THE.BASIC_SILVICULTURE_REPORT WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
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

  /**
   * Everything this mill's data can show about a refused reversal — see {@code
   * SetToDraftIT#fingerprint} for what is and is not read, and why the cost-detail count suffices.
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
      "AC2/AC3/AC4/AC11: all-met Verified track -> 200, V->S, ten categories -> A,"
          + " neither identity pair written")
  void withdrawsAVerification() throws Exception {
    assertThat(trackStatus(HAPPY_MILL)).isEqualTo("V");
    assertThat(categoryStates(HAPPY_MILL)).hasSize(10).containsOnly("V");
    int statusRevisionBefore = statusRevision(HAPPY_MILL);
    int summaryRevisionBefore = minSummaryRevision(HAPPY_MILL);
    int categoryRevisionBefore = minCategoryRevision(HAPPY_MILL);
    int summaryAuditBefore = auditRowCount("ILCR_REPORT_SUMMARY_AUDIT");
    int costDetailAuditBefore = auditRowCount("ILCR_COST_REPORT_DETAIL_AUD");

    mockMvc
        .perform(post(ENDPOINT).param("millId", HAPPY_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trackStatus", is("S")))
        .andExpect(jsonPath("$.message.key", is("sch1-10SubmittedMsg")))
        .andExpect(jsonPath("$.message.text", is(SUBMITTED_MSG)));

    assertTransitionApplied();
    assertNeitherIdentityPairWritten();
    assertEveryRowStamped();
    // The two phases SetToDraftIT ran and this class did not (18.1 code review): the two ITs must
    // hold both reversals to the same bar, or the sibling's presence implies a proof it isn't
    // giving.
    assertRevisionsFollowLegacy(
        statusRevisionBefore, summaryRevisionBefore, categoryRevisionBefore);
    assertNoAuditRowsInserted(summaryAuditBefore, costDetailAuditBefore);
    assertEditabilityFlipped();
  }

  /**
   * {@code REVISION_COUNT} follows legacy entity by entity: the status row is NOT bumped by the
   * reversal statement (legacy's column was plain, never a {@code @Version}); {@code
   * ILCR_REPORT_SUMMARY} and {@code ILCR_REPORT_CATEGORY} ARE, because the sweep dirties rows
   * Hibernate versioned.
   */
  private void assertRevisionsFollowLegacy(
      int statusBefore, int summaryBefore, int categoryBefore) {
    assertThat(statusRevision(HAPPY_MILL)).isEqualTo(statusBefore);
    assertThat(minSummaryRevision(HAPPY_MILL)).isEqualTo(summaryBefore + 1);
    assertThat(minCategoryRevision(HAPPY_MILL)).isEqualTo(categoryBefore + 1);
  }

  /** The application inserts no {@code _AUD} row — delivery triggers own those. */
  private void assertNoAuditRowsInserted(int summaryAuditBefore, int costDetailAuditBefore) {
    assertThat(auditRowCount("ILCR_REPORT_SUMMARY_AUDIT")).isEqualTo(summaryAuditBefore);
    assertThat(auditRowCount("ILCR_COST_REPORT_DETAIL_AUD")).isEqualTo(costDetailAuditBefore);
  }

  /**
   * AC 12 (CHK-018 BR-05): after V&rarr;S the ministry still edits and the Licensee does not —
   * Story 16.1's matrix ({@code ScheduleEditability.java:63-64}), asserted as a consequence.
   */
  private void assertEditabilityFlipped() throws Exception {
    mockMvc
        .perform(
            get("/api/v1/schedule1").param("millId", HAPPY_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.editable", is(true)));
    mockMvc
        .perform(
            get("/api/v1/schedule1")
                .param("millId", HAPPY_MILL)
                .param("year", YEAR)
                .with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.editable", is(false)));
  }

  /**
   * AC2/AC11: the track moved to {@code S} and the ten categories to {@code A}. Legacy mapped both
   * {@code DS} and {@code VS} to {@code A} ({@code SubmitReportDAO:465-487}), so a reversed
   * verification is indistinguishable from a fresh submission at the category level.
   */
  private void assertTransitionApplied() {
    assertThat(trackStatus(HAPPY_MILL)).isEqualTo("S");
    assertThat(categoryStates(HAPPY_MILL)).hasSize(10).containsOnly("A");

    // BR-07: Schedule 11 is seeded to a DIFFERENT code, so a write that reached its column fails.
    assertThat(scalar("MILL_SILVICULTUR_STATUS_CODE", HAPPY_MILL)).isEqualTo("D");
    assertThat(categoryState(HAPPY_MILL, "11")).isEqualTo("S");
    assertThat(categoryUpdateUser(HAPPY_MILL, "11")).isEqualTo(SEED_USER);
    // AC 11's third arm, by value — R__56 seeds this row so the assertion is not vacuous.
    assertThat(silvicultureRow(HAPPY_MILL)).isEqualTo("Reversal Block 791/-/r0");
  }

  /**
   * AC3 and deviation (S). Under legacy's SET list this mill's {@code LICENSEE_*} pair would now
   * hold the ACTING ADMIN's cross-reference, not the submitting licensee's — the admin is
   * associated to mill 791 exactly so that a wrong SET list produces a different, non-null value
   * here rather than a NULL that a laxer assertion might excuse.
   */
  private void assertNeitherIdentityPairWritten() {
    assertThat(scalar("LICENSEE_USER_GUID", HAPPY_MILL)).isEqualTo(SEEDED_LICENSEE_GUID);
    assertThat(identityMillId("LICENSEE_MILL_ID", HAPPY_MILL)).isEqualTo(791L);
    assertThat(scalar("AUDITOR_USER_GUID", HAPPY_MILL)).isEqualTo(SEEDED_AUDITOR_GUID);
    assertThat(identityMillId("AUDITOR_MILL_ID", HAPPY_MILL)).isEqualTo(791L);
  }

  private void assertEveryRowStamped() {
    assertThat(rowCount("ILCR_MILL_REPORT_STATUS", HAPPY_MILL)).isOne();
    assertThat(unstampedRows("ILCR_MILL_REPORT_STATUS", HAPPY_MILL)).isZero();
    assertThat(rowCount("ILCR_REPORT_SUMMARY", HAPPY_MILL)).isPositive();
    assertThat(unstampedRows("ILCR_REPORT_SUMMARY", HAPPY_MILL)).isZero();
    assertThat(summaryCostDetailCount(HAPPY_MILL)).isPositive();
    assertThat(unstampedSummaryCostDetails(HAPPY_MILL)).isZero();
    assertThat(unstampedCategoryRows(HAPPY_MILL)).isZero();
  }

  @Test
  @DisplayName(
      "AC5/AC10 + deviation (V): a failing validation gate -> 409 naming THIS action,"
          + " nothing persisted")
  void refusesWhenTheGateFails() throws Exception {
    // The gate runs before legality, so this Submitted mill is refused for VALIDATION even though
    // S->S would also have been refused as illegal. Legacy's order (CheckStatusMB:247-271) — and
    // the reason this arm is worth having twice: it proves the gate's message wins over the
    // status-legality one, so the admin is told what is actually wrong with the report.
    String before = fingerprint(GATE_FAILS_MILL);

    mockMvc
        .perform(post(ENDPOINT).param("millId", GATE_FAILS_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        .andExpect(jsonPath("$.detail", is(GATE_FAILED_MSG)))
        .andExpect(jsonPath("$.detail", not(is(LEGACY_SUBMIT_GATE_MSG))));

    assertThat(trackStatus(GATE_FAILS_MILL)).isEqualTo("S");
    assertThat(fingerprint(GATE_FAILS_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC7/AC10: the S->S no-op -> 409 setToSubmitNotVerifiedErrorMsg, nothing persisted")
  void refusesANoOp() throws Exception {
    String before = fingerprint(SUBMITTED_MILL);

    mockMvc
        .perform(post(ENDPOINT).param("millId", SUBMITTED_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        .andExpect(jsonPath("$.detail", is(NOT_VERIFIED_STATUS_MSG)));

    assertThat(trackStatus(SUBMITTED_MILL)).isEqualTo("S");
    assertThat(fingerprint(SUBMITTED_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC7/AC10: a Draft track -> 409 — D->S is a legal pair, but it is SUBMIT, not this")
  void refusesADraftTrack() throws Exception {
    // The sharpest arm in this class. TrackTransition.resolve("D","S") DOES return a transition —
    // SUBMIT — so only the .filter(SET_TO_SUBMIT::equals) keeps a licensee's submit from being
    // reachable through an ADMIN-only endpoint that writes a different category state.
    String before = fingerprint(DRAFT_MILL);

    mockMvc
        .perform(post(ENDPOINT).param("millId", DRAFT_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(NOT_VERIFIED_STATUS_MSG)));

    assertThat(trackStatus(DRAFT_MILL)).isEqualTo("D");
    assertThat(categoryStates(DRAFT_MILL)).containsOnly("D");
    assertThat(fingerprint(DRAFT_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC8: a closed mill -> 409 ERR-002, refused before any schedule is read")
  void refusesAClosedMill() throws Exception {
    String before = fingerprint(CLOSED_MILL);

    mockMvc
        .perform(post(ENDPOINT).param("millId", CLOSED_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(ERR_002)));

    assertThat(fingerprint(CLOSED_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC8: missing, blank and non-numeric millId all -> 400 ERR-001 verbatim")
  void refusesABadMillId() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("year", YEAR).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
    mockMvc
        .perform(post(ENDPOINT).param("millId", "  ").param("year", YEAR).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
    mockMvc
        .perform(post(ENDPOINT).param("millId", "not-a-mill").param("year", YEAR).with(admin()))
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
