package ca.bc.gov.nrs.ilcr.checkstatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
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
 * Acceptance test — {@code POST /api/v1/check-status/verify}, the Submitted&rarr;Verified
 * transition (UC-CHK-007/012, FR5). Security ON, which is required rather than incidental: with
 * security off there is no token, so no directory GUID, so the auditor columns would always be NULL
 * and the auditor-recording arm could not be proved at all.
 *
 * <p>Every genuine failure asserts the {@code (status, detail)} pair; the two texts that coincide
 * (a rejected transition and a persistence failure) are distinguishable only by status code.
 *
 * <p>A <em>refused</em> transition answers <strong>409</strong> with {@code
 * reportSubmissionErrorMsg} and writes nothing: a second click on an already-Verified track and the
 * illegal Draft&harr;Verified jump are both rejections. An earlier cut returned 200 for those as
 * decision D4 (legacy parity); {@code d9952af} reverted it, because UC-CHK-007's own slice
 * catalogue titles that behaviour a <em>known defect</em> ("Verification Silently Reports Success
 * Despite Rejected Transition"), and the epic's rule is legacy-wins <em>except</em> where the use
 * cases record legacy as defective. Those arms assert the 409, the stored {@code trackStatus}, and
 * the before/after fingerprint — the fingerprint being what keeps a refusal from covering a silent
 * write.
 *
 * <p>Mills are this class's own ({@code R__55}). Verifying mutates the status row, ten category
 * rows and thirteen tables' audit columns, so no mill here may be shared with another suite, and
 * none of the mills {@code CheckStatusSweepIT} fingerprints is touched. Only 764 and 769 are
 * mutated, by one test each.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("POST /api/v1/check-status/verify — the Submitted->Verified transition (Story 17.1)")
class VerifyReportIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/check-status/verify";
  private static final String PROBLEM_JSON = "application/problem+json";
  private static final String YEAR = "2021";

  private static final String HAPPY_MILL = "764";
  private static final String GATE_FAILS_MILL = "765";
  private static final String DRAFT_MILL = "766";
  private static final String VERIFIED_MILL = "767";
  private static final String CLOSED_MILL = "768";
  private static final String NO_XREF_MILL = "769";

  /** The admin seeded with an {@code ILCR_MILL_USER_XREF} row for mill 764, and only 764. */
  private static final String ADMIN_GUID = "VERIFYADMIN0000111122223333AAAA1";

  /** The principal name, which is what lands in the audit columns (30-char limit). */
  private static final String ACTING_USER = "verifyadmin";

  /**
   * The token's {@code sub} — deliberately different from {@link #ACTING_USER}, and deliberately
   * the 36-char Cognito UUID shape that would overflow {@code UPDATE_USERID VARCHAR2(30)}. If the
   * app ever stamps the subject instead of {@code custom:idp_username}, the audit assertions fail
   * rather than silently agreeing.
   */
  private static final String COGNITO_SUB = "11111111-2222-3333-4444-555555555555";

  /** What the fixture seeds into the audit columns it populates at all. */
  private static final String SEED_USER = "SEED";

  private static final String VERIFIED_MSG = "Schedules 1-10 status has been updated to verified.";
  private static final String NOT_SUBMITTED_MSG =
      "The report cannot be submitted. One or more of the Schedules have not passed validation."
          + " Please review and correct any errors.";
  private static final String SUBMISSION_ERROR_MSG =
      "An error has been found submitting schedules. The error details have been logged."
          + " Please contact ILCR application support.";

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
   * An admin whose token carries a directory GUID. The group-only helper the sibling authorization
   * IT uses would leave {@code custom:idp_user_id} absent, which resolves to no cross-reference and
   * writes NULL — so an auditor arm built on it would silently test the wrong branch.
   *
   * <p>Built through the PRODUCTION converter, and {@code sub} is deliberately NOT the acting user.
   * {@code spring-security-test}'s {@code jwt()} constructs the token itself and never calls {@link
   * FamJwtAuthenticationConverter}, so the principal name falls back to {@code sub}: seeding {@code
   * sub} with the acting user (as this class first did) made the stamped-actor assertion pass
   * whichever claim the app read, harness or app alike. Converting the Jwt here means {@code
   * getName()} comes from {@code auditUsername}'s {@code custom:idp_username}, so the assertion now
   * fails if that resolution regresses — and {@code sub} is a 36-char UUID shape precisely because
   * falling back to it would overflow the {@code VARCHAR2(30)} audit column (ORA-12899) in
   * production.
   */
  private RequestPostProcessor adminWithGuid(String guid) {
    Jwt token =
        Jwt.withTokenValue("verify-it-token")
            .header("alg", "none")
            .subject(COGNITO_SUB)
            .claim("idir_user_guid", guid)
            .claim("idir_username", ACTING_USER)
            .claim("identity_provider", "azureidir")
            .claim("client_roles", List.of("ILCR_ADMIN"))
            .build();
    return authentication(CONVERTER.convert(token));
  }

  private RequestPostProcessor admin() {
    return adminWithGuid(ADMIN_GUID);
  }

  private String trackStatus(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT ILCR_MILL_REPORT_STATUS_CODE FROM THE.ILCR_MILL_REPORT_STATUS"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
        Integer.valueOf(mill));
  }

  private String silvicultureStatus(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT MILL_SILVICULTUR_STATUS_CODE FROM THE.ILCR_MILL_REPORT_STATUS"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
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

  private String auditorGuid(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT AUDITOR_USER_GUID FROM THE.ILCR_MILL_REPORT_STATUS"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        String.class,
        Integer.valueOf(mill));
  }

  private Long auditorMillId(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT AUDITOR_MILL_ID FROM THE.ILCR_MILL_REPORT_STATUS"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        Long.class,
        Integer.valueOf(mill));
  }

  /**
   * Rows of {@code table} for this mill/year that the acting user did NOT stamp.
   *
   * <p>A COUNT of the unstamped, not {@code MAX(UPDATE_USERID)}, which this class used first:
   * {@code 'verifyadmin'} sorts above the fixture's {@code 'SEED'}, so MAX returned the actor as
   * soon as ONE row was stamped and a sweep narrowed to a single category would still have passed.
   * Paired with {@link #rowCount} at every call site so a table that is simply empty cannot satisfy
   * the assertion vacuously.
   */
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

  private int rowCount(String table, String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE." + table + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        Integer.class,
        Integer.valueOf(mill));
  }

  /**
   * Unstamped category rows among ids {@code '1'}-{@code '10'} only — {@code '11'} must NOT move.
   */
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

  private String categoryUpdateUser(String mill, String categoryId) {
    return jdbcTemplate.queryForObject(
        "SELECT UPDATE_USERID FROM THE.ILCR_REPORT_CATEGORY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021 AND ILCR_CATEGORY_ID = ?",
        String.class,
        Integer.valueOf(mill),
        categoryId);
  }

  /**
   * The cost-detail rows hanging off this mill's Schedule 1/2/3 summaries that the actor did NOT
   * stamp. {@code ILCR_COST_REPORT_DETAIL} carries no mill/year of its own, which is why it needed
   * its own helper — and why AC3's fourth table had no assertion at all before this.
   */
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

  private int summaryCostDetailCount(String mill) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE.ILCR_COST_REPORT_DETAIL d"
            + " WHERE d.ILCR_REPORT_SUMMARY_ID IN ("
            + "   SELECT s.ILCR_REPORT_SUMMARY_ID FROM THE.ILCR_REPORT_SUMMARY s"
            + "    WHERE s.ILCR_MILL_ID = ? AND s.REPORT_YEAR = 2021)",
        Integer.class,
        Integer.valueOf(mill));
  }

  /** A named wrong-category row's actor, which a correctly scoped sweep never touches. */
  private String decoyUpdateUser(String table, String idColumn, long id) {
    return jdbcTemplate.queryForObject(
        "SELECT UPDATE_USERID FROM THE." + table + " WHERE " + idColumn + " = ?", String.class, id);
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
   * Everything a refused verify must leave byte-identical: the status row (code, revision, both
   * auditor columns, actor), every one of the eleven category rows with its actor, and the audit
   * columns of the summaries and their cost details.
   *
   * <p>Task 9 pinned a before/after fingerprint on every "nothing persisted" arm and the arms
   * asserted two or three columns instead, so a stray audit stamp inside a refused request passed
   * all of them. Row counts alone cannot catch that — a stamp changes no count — so this reads the
   * audit columns themselves.
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
      "AC1/AC2/AC3: all-met Submitted track -> 200, S->V, ten categories -> V, auditor recorded")
  void verifiesSubmittedTrack() throws Exception {
    assertThat(trackStatus(HAPPY_MILL)).isEqualTo("S");
    int statusRevisionBefore = statusRevision(HAPPY_MILL);
    int summaryRevisionBefore = minSummaryRevision(HAPPY_MILL);
    int categoryRevisionBefore = minCategoryRevision(HAPPY_MILL);
    int summaryAuditBefore = auditRowCount("ILCR_REPORT_SUMMARY_AUDIT");
    int costDetailAuditBefore = auditRowCount("ILCR_COST_REPORT_DETAIL_AUD");

    mockMvc
        .perform(post(ENDPOINT).param("millId", HAPPY_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.message.key", is("sch1-10VerifiedMsg")))
        .andExpect(jsonPath("$.message.text", is(VERIFIED_MSG)));

    // Four phases, each a named method rather than one 29-assertion block. The verify MUTATES this
    // mill, so they cannot be separate @Test methods -- a second POST would answer 409.
    assertTransitionApplied();
    assertEveryRowStamped();
    assertRevisionsFollowLegacy(
        statusRevisionBefore, summaryRevisionBefore, categoryRevisionBefore);
    assertNoAuditRowsInserted(summaryAuditBefore, costDetailAuditBefore);
    assertWrongCategoryDecoysUntouched();
  }

  /**
   * AC1/AC2: the track moved, the ten categories with it, Schedule 11 did not, auditor recorded.
   */
  private void assertTransitionApplied() {
    assertThat(trackStatus(HAPPY_MILL)).isEqualTo("V");
    assertThat(categoryStates(HAPPY_MILL)).hasSize(10).containsOnly("V");

    // Track independence (CHK-012 S09): Schedule 11's status and its category row are untouched.
    assertThat(silvicultureStatus(HAPPY_MILL)).isEqualTo("D");
    assertThat(categoryState(HAPPY_MILL, "11")).isEqualTo("D");

    // The auditor is a composite key, asserted by value — non-null alone would pass on the wrong
    // row.
    assertThat(auditorGuid(HAPPY_MILL)).isEqualTo(ADMIN_GUID);
    assertThat(auditorMillId(HAPPY_MILL)).isEqualTo(764L);
  }

  /**
   * AC3: EVERY row stamped, not merely one. Each assertion is paired with its row count so an empty
   * table cannot satisfy it vacuously.
   */
  private void assertEveryRowStamped() {
    assertThat(rowCount("ILCR_MILL_REPORT_STATUS", HAPPY_MILL)).isOne();
    assertThat(unstampedRows("ILCR_MILL_REPORT_STATUS", HAPPY_MILL)).isZero();

    assertThat(rowCount("ILCR_REPORT_SUMMARY", HAPPY_MILL)).isPositive();
    assertThat(unstampedRows("ILCR_REPORT_SUMMARY", HAPPY_MILL)).isZero();

    // AC3's fourth table, which had no assertion at all: the cost details under those summaries.
    assertThat(summaryCostDetailCount(HAPPY_MILL)).isPositive();
    assertThat(unstampedSummaryCostDetails(HAPPY_MILL)).isZero();

    // Categories '1'-'10' all stamped; '11' byte-identical, asserted on the column rather than
    // through an aggregate that could not distinguish the two.
    assertThat(unstampedCategoryRows(HAPPY_MILL)).isZero();
    assertThat(categoryUpdateUser(HAPPY_MILL, "11")).isEqualTo(SEED_USER);
  }

  /**
   * {@code REVISION_COUNT} follows legacy entity by entity: the status row is NOT bumped (a plain
   * {@code @Column}), while {@code ILCR_REPORT_SUMMARY} and {@code ILCR_REPORT_CATEGORY} are
   * ({@code @Version} at {@code ILCRReportSummary:82} / {@code ILCRReportCategory:39}, which
   * Hibernate incremented when the sweep dirtied them). Load-bearing on the summary: it is the row
   * {@code StaleRevisionException} guards, so legacy REJECTED a concurrent schedule save holding
   * revision n after a verify.
   */
  private void assertRevisionsFollowLegacy(
      int statusBefore, int summaryBefore, int categoryBefore) {
    assertThat(statusRevision(HAPPY_MILL)).isEqualTo(statusBefore);
    assertThat(minSummaryRevision(HAPPY_MILL)).isEqualTo(summaryBefore + 1);
    assertThat(minCategoryRevision(HAPPY_MILL)).isEqualTo(categoryBefore + 1);
  }

  /**
   * AC3: the application inserts no {@code _AUD} row — delivery triggers own those, and the test
   * snapshot creates the shadow tables without them ({@code V20260910}), so this is directly
   * provable.
   */
  private void assertNoAuditRowsInserted(int summaryAuditBefore, int costDetailAuditBefore) {
    assertThat(auditRowCount("ILCR_REPORT_SUMMARY_AUDIT")).isEqualTo(summaryAuditBefore);
    assertThat(auditRowCount("ILCR_COST_REPORT_DETAIL_AUD")).isEqualTo(costDetailAuditBefore);
  }

  /**
   * PARITY: legacy reached five of the thirteen audit tables through a DAO call carrying an {@code
   * ilcr_category} id, so a row of another category was never stamped. {@code R__55} seeds one
   * wrong-category decoy in EACH of those five tables for this mill; each must still read {@code
   * SEED}. Drop the {@code ILCR_CATEGORY_ID} predicate from the sweep and every one flips.
   *
   * <p>The last three hide the category in their DAO signature ({@code Schedule4DAO:390}, {@code
   * Schedule5DAO:308}, {@code Schedule8DAO:134} each bind it internally) — legacy filtered these
   * too, which an earlier cut got wrong by reading the signatures instead of the named queries.
   */
  private void assertWrongCategoryDecoysUntouched() {
    assertThat(decoyUpdateUser("ROAD_MAINTENANCE_REPORT", "ROAD_MAINTENANCE_REPORT_ID", 1078))
        .isEqualTo(SEED_USER);
    assertThat(decoyUpdateUser("CONTRACTUAL_WORK_REPORT", "CONTRACTUAL_WORK_REPORT_ID", 1079))
        .isEqualTo(SEED_USER);
    assertThat(decoyUpdateUser("BRIDGE_REPORT", "BRIDGE_REPORT_ID", 1080)).isEqualTo(SEED_USER);
    assertThat(decoyUpdateUser("CULVERT_REPORT", "CULVERT_REPORT_ID", 1081)).isEqualTo(SEED_USER);
    assertThat(decoyUpdateUser("ROAD_CONSTRUCTION_REPRT", "ROAD_CONSTRUCTION_REPRT_ID", 1082))
        .isEqualTo(SEED_USER);
    assertThat(decoyUpdateUser("TRANSPORTATION_REPORT", "TRANSPORTATION_REPORT_ID", 1083))
        .isEqualTo(SEED_USER);
    assertThat(decoyUpdateUser("CAMP_REPORT", "CAMP_REPORT_ID", 1084)).isEqualTo(SEED_USER);
    assertThat(decoyUpdateUser("TREE_TO_TRUCK_REPORT", "TREE_TO_TRUCK_REPORT_ID", 1085))
        .isEqualTo(SEED_USER);
  }

  @Test
  @DisplayName("AC2: an admin with no mill association verifies, and both auditor columns are NULL")
  void recordsNoAuditorWithoutAnAssociation() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("millId", NO_XREF_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trackStatus", is("V")));

    assertThat(trackStatus(NO_XREF_MILL)).isEqualTo("V");
    assertThat(auditorGuid(NO_XREF_MILL)).isNull();
    assertThat(auditorMillId(NO_XREF_MILL)).isNull();
  }

  @Test
  @DisplayName(
      "AC4/AC10: a failing validation gate -> 409 reportNotSubmittedErrorMsg, nothing persisted")
  void refusesWhenTheGateFails() throws Exception {
    String before = fingerprint(GATE_FAILS_MILL);

    mockMvc
        .perform(post(ENDPOINT).param("millId", GATE_FAILS_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        .andExpect(jsonPath("$.detail", is(NOT_SUBMITTED_MSG)));

    assertThat(trackStatus(GATE_FAILS_MILL)).isEqualTo("S");
    assertThat(categoryStates(GATE_FAILS_MILL)).containsOnly("A");
    assertThat(auditorGuid(GATE_FAILS_MILL)).isNull();
    assertThat(fingerprint(GATE_FAILS_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC5/AC10: a Draft track -> 409 reportSubmissionErrorMsg (the illegal D->V jump)")
  void refusesADraftTrack() throws Exception {
    String before = fingerprint(DRAFT_MILL);

    mockMvc
        .perform(post(ENDPOINT).param("millId", DRAFT_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(SUBMISSION_ERROR_MSG)));

    assertThat(trackStatus(DRAFT_MILL)).isEqualTo("D");
    assertThat(categoryStates(DRAFT_MILL)).containsOnly("D");
    assertThat(fingerprint(DRAFT_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC5/AC10: a second click on an already-Verified track -> 409, nothing persisted")
  void refusesANoOp() throws Exception {
    String before = fingerprint(VERIFIED_MILL);

    // Legacy's outcome, via ILCRService.submitReport:718-723 -> ILCSException -> the bean's catch.
    mockMvc
        .perform(post(ENDPOINT).param("millId", VERIFIED_MILL).param("year", YEAR).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(SUBMISSION_ERROR_MSG)));

    assertThat(trackStatus(VERIFIED_MILL)).isEqualTo("V");
    assertThat(fingerprint(VERIFIED_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC6: an ILCR_SUBMITTER lacks SET_REPORT_STATUS -> 403, nothing persisted")
  void refusesASubmitter() throws Exception {
    String before = fingerprint(GATE_FAILS_MILL);

    mockMvc
        .perform(
            post(ENDPOINT)
                .param("millId", GATE_FAILS_MILL)
                .param("year", YEAR)
                .with(canonicalSubmitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));

    assertThat(trackStatus(GATE_FAILS_MILL)).isEqualTo("S");
    assertThat(fingerprint(GATE_FAILS_MILL)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC7: a closed mill -> 409 ERR-002, refused before any schedule is read")
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
  @DisplayName("AC8: missing year -> 400 ERR-001 (the year half was untested)")
  void refusesAMissingYear() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("millId", HAPPY_MILL).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
  }

  @Test
  @DisplayName("AC8: blank year -> 400 ERR-001")
  void refusesABlankYear() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("millId", HAPPY_MILL).param("year", "  ").with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
  }

  @Test
  @DisplayName("AC8: non-numeric year -> 400 ERR-001, never Spring's generic 400")
  void refusesANonNumericYear() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("millId", HAPPY_MILL).param("year", "twenty21").with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
  }

  @Test
  @DisplayName("AC9: an unknown mill -> 404 with the Check Status page's own not-found text")
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
