package ca.bc.gov.nrs.ilcr.checkstatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.json.JsonCompareMode;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test — Story 26.3 AC 1/2/4/5/7. {@code POST /api/v1/check-status/schedule11/verify}
 * moves the silviculture track Submitted → Verified in one committed transaction, or refuses and
 * writes nothing.
 *
 * <p>Security ON, which is required rather than incidental (the 17.1 trap): with security off there
 * is no token and so no directory GUID, and the auditor-recording arm would silently exercise the
 * NULL branch. The admin token carries {@code custom:idp_user_id} and is converted through the
 * production converter, so the audit name comes from {@code custom:idp_username}.
 *
 * <p>Fixtures ({@code R__59}): 807 (happy path), 813 (no admin xref), 814 (zero locations) and 815
 * (a 1–10 verify on an S/S mill) are each verified here exactly once; 811 is the rollback arm and
 * can never succeed; 808, 809 and 810 are refused and never written. 812 is {@code
 * Schedule11VerifyConcurrencyIT}'s.
 *
 * <p><strong>Every "unchanged" is asserted by reading the value before and after.</strong>
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName(
    "POST /api/v1/check-status/schedule11/verify — Schedule 11 Submitted -> Verified (26.3)")
class Schedule11VerifyIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/check-status/schedule11/verify";
  private static final String PROBLEM_JSON = "application/problem+json";

  private static final String VERIFIED = "Schedule 11 status has been updated to verified.";
  private static final String ONE_TO_TEN_VERIFIED =
      "Schedules 1-10 status has been updated to verified.";
  private static final String NOT_SUBMITTED =
      "The report cannot be submitted. One or more of the Schedules have not passed validation."
          + " Please review and correct any errors.";
  private static final String SUBMISSION_ERROR =
      "An error has been found submitting schedules. The error details have been logged. Please"
          + " contact ILCR application support.";
  private static final String ERR_001 = "Please Select Mill and Reporting Year in the Home Page. ";
  private static final String CHECK_STATUS_NOT_FOUND =
      "One or more of the schedules for the report have not been found.";
  private static final String ERR_002 =
      "This Mill is not active for the current Reporting Year. "
          + "Please select another mill from the Home Page.";

  /** R__59's acting admin, cross-referenced to mill 807 and to no other. */
  private static final String ADMIN_GUID = "VERIFY11ADMIN000111122223333AAA1";

  /** The auditor R__59 records on 807 and 813 before any verify runs. */
  private static final String OLD_AUDITOR_GUID = "VERIFY11OLDAUDITOR00011112222AA1";

  /** The licensee R__59 records on 807 — a verify must leave it alone. */
  private static final String LICENSEE_GUID = "VERIFY11LICENSEE000111122223AA11";

  /** The audit name, from {@code custom:idp_username} (30-char column). */
  private static final String ACTING_USER = "verify11admin";

  /** A 36-char {@code sub} that would overflow the audit column if the app ever stamped it. */
  private static final String COGNITO_SUB = "26262626-3333-4444-5555-666666666666";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  private static final List<String> TABLES =
      List.of(
          "ILCR_REPORT_SUMMARY",
          "ILCR_COST_REPORT_DETAIL",
          "BASIC_SILVICULTURE_REPORT",
          "ILCR_MILL_REPORT_STATUS",
          "ILCR_REPORT_CATEGORY");

  @MockitoBean private JwtDecoder jwtDecoder;
  @Autowired private JdbcTemplate jdbc;

  private static RequestPostProcessor admin() {
    Jwt token =
        Jwt.withTokenValue("verify11-it-token")
            .header("alg", "none")
            .subject(COGNITO_SUB)
            .claim("idir_user_guid", ADMIN_GUID)
            .claim("idir_username", ACTING_USER)
            .claim("identity_provider", "azureidir")
            .claim("client_roles", List.of("ILCR_ADMIN"))
            .build();
    return authentication(CONVERTER.convert(token));
  }

  private static MockHttpServletRequestBuilder verify11(long mill, int year) {
    return post(ENDPOINT)
        .param("millId", String.valueOf(mill))
        .param("year", String.valueOf(year))
        .accept(MediaType.APPLICATION_JSON)
        .with(admin());
  }

  private static MockHttpServletRequestBuilder sweep(long mill) {
    return get("/api/v1/check-status")
        .param("millId", String.valueOf(mill))
        .param("year", "2021")
        .accept(MediaType.APPLICATION_JSON);
  }

  private static MockHttpServletRequestBuilder schedule11Page(long mill) {
    return get("/api/v1/schedule11")
        .param("millId", String.valueOf(mill))
        .param("year", "2021")
        .accept(MediaType.APPLICATION_JSON);
  }

  /** Per table the row count, revision sum and latest touch, plus the mill's own rows. */
  private String footprint(long mill) {
    StringBuilder f = new StringBuilder();
    for (String table : TABLES) {
      f.append(table)
          .append('=')
          .append(
              jdbc.queryForObject(
                  "SELECT COUNT(*) || '/' || NVL(SUM(REVISION_COUNT), 0) || '/'"
                      + " || NVL(TO_CHAR(CAST(MAX(UPDATE_TIMESTAMP) AS TIMESTAMP),"
                      + " 'YYYY-MM-DD HH24:MI:SS.FF6'), '-')"
                      + " FROM THE."
                      + table,
                  String.class))
          .append(';');
    }
    f.append("STATUS=").append(statusRow(mill)).append(';');
    f.append("CATEGORIES=").append(categoryRows(mill));
    return f.toString();
  }

  private Map<String, Object> statusRow(long mill) {
    return jdbc.queryForMap(
        "SELECT ILCR_MILL_REPORT_STATUS_CODE, MILL_SILVICULTUR_STATUS_CODE, REPORT_COMPLETED_IND,"
            + " LICENSEE_MILL_ID, LICENSEE_USER_GUID, AUDITOR_MILL_ID, AUDITOR_USER_GUID,"
            + " REVISION_COUNT, UPDATE_USERID, UPDATE_TIMESTAMP, ENTRY_TIMESTAMP"
            + " FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        mill);
  }

  private List<Map<String, Object>> categoryRows(long mill) {
    return jdbc.queryForList(
        "SELECT ILCR_CATEGORY_ID, CATEGORY_STATE_CODE, REVISION_COUNT, UPDATE_USERID,"
            + " UPDATE_TIMESTAMP FROM THE.ILCR_REPORT_CATEGORY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021 ORDER BY TO_NUMBER(ILCR_CATEGORY_ID)",
        mill);
  }

  /** Categories '1'..'10' only — everything a Schedule 11 transition must never write. */
  private List<Map<String, Object>> oneToTenCategories(long mill) {
    return categoryRows(mill).stream()
        .filter(r -> !"11".equals(r.get("ILCR_CATEGORY_ID")))
        .toList();
  }

  private Map<String, Object> categoryEleven(long mill) {
    return categoryRows(mill).stream()
        .filter(r -> "11".equals(r.get("ILCR_CATEGORY_ID")))
        .findFirst()
        .orElseThrow();
  }

  private List<Map<String, Object>> locations(long mill) {
    return jdbc.queryForList(
        "SELECT BASIC_SILVICULTURE_REPORT_ID, REVISION_COUNT, UPDATE_USERID, UPDATE_TIMESTAMP"
            + " FROM THE.BASIC_SILVICULTURE_REPORT WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021"
            + " ORDER BY BASIC_SILVICULTURE_REPORT_ID",
        mill);
  }

  private List<Map<String, Object>> locationCosts(long mill) {
    return jdbc.queryForList(
        "SELECT d.ILCR_COST_REPORT_DETAIL_ID, d.COST, d.REVISION_COUNT, d.UPDATE_USERID,"
            + " d.UPDATE_TIMESTAMP"
            + " FROM THE.ILCR_COST_REPORT_DETAIL d JOIN THE.BASIC_SILVICULTURE_REPORT b"
            + " ON b.BASIC_SILVICULTURE_REPORT_ID = d.BASIC_SILVICULTURE_REPORT_ID"
            + " WHERE b.ILCR_MILL_ID = ? AND b.REPORT_YEAR = 2021"
            + " ORDER BY d.ILCR_COST_REPORT_DETAIL_ID",
        mill);
  }

  /** One row by primary key — its audit and revision columns — for the "never stamped" reads. */
  private Map<String, Object> auditColumns(String table, String idColumn, long id) {
    return jdbc.queryForMap(
        "SELECT REVISION_COUNT, UPDATE_USERID, UPDATE_TIMESTAMP FROM THE."
            + table
            + " WHERE "
            + idColumn
            + " = ?",
        id);
  }

  @Test
  @DisplayName(
      "AC 1/7a: 807 silviculture S, 1-10 D -> 200 sch11VerifiedMsg; V, auditor overwritten,"
          + " locations stamped, '11' at V — and 1-10 byte-unchanged")
  void happyPath_verifiesSchedule11Alone() throws Exception {
    Map<String, Object> before = statusRow(807);
    List<Map<String, Object>> oneToTenBefore = oneToTenCategories(807);
    List<Map<String, Object>> costsBefore = locationCosts(807);
    // Out of scope, each read by key: 807's own Schedules 1-10 row family (R__59 seeds it for
    // exactly this), and a neighbour mill's Schedule 11 location and cost. A Schedule 11 verify
    // that also ran the twenty 1-10 touches, or whose touch lost its mill/year predicate, stamps
    // one of these.
    Map<String, Object> oneToTenSummaryBefore =
        auditColumns("ILCR_REPORT_SUMMARY", "ILCR_REPORT_SUMMARY_ID", 1684);
    Map<String, Object> oneToTenCostBefore =
        auditColumns("ILCR_COST_REPORT_DETAIL", "ILCR_COST_REPORT_DETAIL_ID", 5864);
    Map<String, Object> neighbourLocationBefore =
        auditColumns("BASIC_SILVICULTURE_REPORT", "BASIC_SILVICULTURE_REPORT_ID", 9433);
    Map<String, Object> neighbourCostBefore =
        auditColumns("ILCR_COST_REPORT_DETAIL", "ILCR_COST_REPORT_DETAIL_ID", 5850);
    assertThat(before.get("MILL_SILVICULTUR_STATUS_CODE")).isEqualTo("S");
    assertThat(before.get("ILCR_MILL_REPORT_STATUS_CODE")).isEqualTo("D");
    // The seeded pair a verify must REPLACE (D1), so "the auditor was written" cannot pass on a
    // column that simply already held the right value.
    assertThat(before.get("AUDITOR_USER_GUID")).isEqualTo(OLD_AUDITOR_GUID);
    // Both halves differ from what the verify writes (807), so each column's overwrite is observed.
    assertThat(((Number) before.get("AUDITOR_MILL_ID")).longValue()).isEqualTo(813L);

    mockMvc
        .perform(verify11(807, 2021))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(
            content()
                .json(
                    "{\"trackStatus\":\"V\",\"message\":{\"key\":\"sch11VerifiedMsg\",\"text\":\""
                        + VERIFIED
                        + "\"}}",
                    JsonCompareMode.STRICT));

    Map<String, Object> after = statusRow(807);
    assertThat(after.get("MILL_SILVICULTUR_STATUS_CODE")).isEqualTo("V");
    assertThat(after.get("ILCR_MILL_REPORT_STATUS_CODE"))
        .isEqualTo(before.get("ILCR_MILL_REPORT_STATUS_CODE"));
    // D1: the shared AUDITOR pair now names this admin's 807 assignment, having replaced the seed.
    assertThat(((Number) after.get("AUDITOR_MILL_ID")).longValue()).isEqualTo(807L);
    assertThat(after.get("AUDITOR_USER_GUID")).isEqualTo(ADMIN_GUID);
    // A verify writes the auditor pair only; who submitted stays recorded.
    assertThat(after.get("LICENSEE_MILL_ID")).isEqualTo(before.get("LICENSEE_MILL_ID"));
    assertThat(after.get("LICENSEE_USER_GUID"))
        .isEqualTo(before.get("LICENSEE_USER_GUID"))
        .isEqualTo(LICENSEE_GUID);
    assertThat(after.get("REPORT_COMPLETED_IND")).isEqualTo(before.get("REPORT_COMPLETED_IND"));
    // D3: no REVISION_COUNT bump, as the 1-10 verify statement does not bump either.
    assertThat(after.get("REVISION_COUNT")).isEqualTo(before.get("REVISION_COUNT"));
    assertThat(after.get("UPDATE_USERID")).isEqualTo(ACTING_USER);
    assertThat((Timestamp) after.get("UPDATE_TIMESTAMP"))
        .isAfter((Timestamp) before.get("UPDATE_TIMESTAMP"));

    // Categories '1'..'10' read back identical, value for value; '11' advanced A -> V.
    assertThat(oneToTenCategories(807)).isEqualTo(oneToTenBefore);
    Map<String, Object> eleven = categoryEleven(807);
    assertThat(eleven.get("CATEGORY_STATE_CODE")).isEqualTo("V");
    assertThat(((Number) eleven.get("REVISION_COUNT")).intValue()).isEqualTo(1);
    assertThat(eleven.get("UPDATE_USERID")).isEqualTo(ACTING_USER);

    // Every location and every cost under it stamped, no revision or value moved.
    List<Map<String, Object>> locations = locations(807);
    assertThat(locations).hasSize(2);
    for (Map<String, Object> row : locations) {
      assertThat(row.get("UPDATE_USERID")).as(row.toString()).isEqualTo(ACTING_USER);
      assertThat(row.get("UPDATE_TIMESTAMP")).isNotNull();
      assertThat(((Number) row.get("REVISION_COUNT")).intValue()).isZero();
    }
    List<Map<String, Object>> costs = locationCosts(807);
    assertThat(costs).hasSize(4);
    for (int i = 0; i < costs.size(); i++) {
      assertThat(costs.get(i).get("UPDATE_USERID")).isEqualTo(ACTING_USER);
      assertThat(costs.get(i).get("COST")).isEqualTo(costsBefore.get(i).get("COST"));
      assertThat(costs.get(i).get("REVISION_COUNT"))
          .isEqualTo(costsBefore.get(i).get("REVISION_COUNT"));
    }

    assertThat(auditColumns("ILCR_REPORT_SUMMARY", "ILCR_REPORT_SUMMARY_ID", 1684))
        .as("807's Schedules 1-10 summary is not the Schedule 11 verify's to stamp")
        .isEqualTo(oneToTenSummaryBefore);
    assertThat(auditColumns("ILCR_COST_REPORT_DETAIL", "ILCR_COST_REPORT_DETAIL_ID", 5864))
        .isEqualTo(oneToTenCostBefore);
    assertThat(auditColumns("BASIC_SILVICULTURE_REPORT", "BASIC_SILVICULTURE_REPORT_ID", 9433))
        .as("808's Schedule 11 location is outside 807/2021")
        .isEqualTo(neighbourLocationBefore);
    assertThat(auditColumns("ILCR_COST_REPORT_DETAIL", "ILCR_COST_REPORT_DETAIL_ID", 5850))
        .isEqualTo(neighbourCostBefore);

    // The page's re-sweep, and editability per the 16.1 matrix: ADMIN still edits at V (CHK-008
    // BR-06, DL-23 widening the legacy Auditor's read-only); the SUBMITTER does not.
    mockMvc
        .perform(sweep(807).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.schedule11.statusCode", is("V")))
        .andExpect(jsonPath("$.schedules1To10.statusCode", is("D")));
    mockMvc
        .perform(schedule11Page(807).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.editable", is(true)));
    mockMvc
        .perform(schedule11Page(807).with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.editable", is(false)));
  }

  @Test
  @DisplayName(
      "AC 2: 808 a location without a Planned Cost -> 409 reportNotSubmittedErrorMsg, nothing"
          + " written, the flag visible on re-sweep")
  void gateFails_409_writesNothing() throws Exception {
    String before = footprint(808);

    mockMvc
        .perform(verify11(808, 2021))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        .andExpect(jsonPath("$.detail", is(NOT_SUBMITTED)));

    assertThat(footprint(808)).isEqualTo(before);
    mockMvc
        .perform(sweep(808).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.schedule11.statusCode", is("S")))
        .andExpect(jsonPath("$.schedule11.requirementsMet", is(false)))
        .andExpect(
            jsonPath(
                "$.schedule11.schedules[0].verdict.errors[0].text",
                is("location  : Unfinished Block - Planned cost: Value Required")));
  }

  @Test
  @DisplayName("AC 5: 809 silviculture D -> the D->V jump is 409 reportSubmissionErrorMsg")
  void draft_409_genericText() throws Exception {
    String before = footprint(809);

    mockMvc
        .perform(verify11(809, 2021))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        .andExpect(jsonPath("$.detail", is(SUBMISSION_ERROR)));

    assertThat(footprint(809)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC 5: 810 silviculture V -> the V->V no-op is 409 reportSubmissionErrorMsg")
  void alreadyVerified_409_genericText() throws Exception {
    String before = footprint(810);

    mockMvc
        .perform(verify11(810, 2021))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        .andExpect(jsonPath("$.detail", is(SUBMISSION_ERROR)));

    assertThat(footprint(810)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC 5: 514 carries a NULL silviculture code -> 409 generic text, nothing written")
  void nullSilvicultureCode_409_genericText() throws Exception {
    assertThat(statusRow(514).get("MILL_SILVICULTUR_STATUS_CODE")).isNull();
    String before = footprint(514);

    mockMvc
        .perform(verify11(514, 2021))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(SUBMISSION_ERROR)));

    assertThat(footprint(514)).isEqualTo(before);
  }

  @Test
  @DisplayName(
      "AC 5: 811 with no category '11' row -> 500 reportSubmissionErrorMsg, the whole transition"
          + " rolled back — silviculture still S")
  void missingCategoryRow_500_rollsBack() throws Exception {
    Map<String, Object> before = statusRow(811);
    List<Map<String, Object>> categoriesBefore = categoryRows(811);
    List<Map<String, Object>> locationsBefore = locations(811);
    List<Map<String, Object>> costsBefore = locationCosts(811);

    mockMvc
        .perform(verify11(811, 2021))
        .andExpect(status().isInternalServerError())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
        .andExpect(jsonPath("$.detail", is(SUBMISSION_ERROR)));

    // The status UPDATE and both touches ran before the category advance found no row.
    assertThat(statusRow(811)).isEqualTo(before);
    assertThat(statusRow(811).get("MILL_SILVICULTUR_STATUS_CODE")).isEqualTo("S");
    assertThat(categoryRows(811)).isEqualTo(categoriesBefore);
    assertThat(locations(811)).isEqualTo(locationsBefore);
    assertThat(locationCosts(811)).isEqualTo(costsBefore);
  }

  @Test
  @DisplayName(
      "AC 1/D1: 813 the admin has no xref -> 200 with a NULL auditor, erasing the recorded pair;"
          + " the S/S mill's 1-10 track is untouched")
  void noXref_recordsNullAuditor() throws Exception {
    Map<String, Object> before = statusRow(813);
    List<Map<String, Object>> oneToTenBefore = oneToTenCategories(813);
    assertThat(before.get("AUDITOR_USER_GUID")).isEqualTo(OLD_AUDITOR_GUID);

    mockMvc
        .perform(verify11(813, 2021))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.message.key", is("sch11VerifiedMsg")));

    Map<String, Object> after = statusRow(813);
    assertThat(after.get("MILL_SILVICULTUR_STATUS_CODE")).isEqualTo("V");
    // Legacy's erase path: the xref miss writes NULLs over the pair the other verify recorded.
    assertThat(after.get("AUDITOR_MILL_ID")).isNull();
    assertThat(after.get("AUDITOR_USER_GUID")).isNull();
    assertThat(after.get("ILCR_MILL_REPORT_STATUS_CODE"))
        .isEqualTo(before.get("ILCR_MILL_REPORT_STATUS_CODE"))
        .isEqualTo("S");
    assertThat(oneToTenCategories(813)).isEqualTo(oneToTenBefore);

    // 1-10 is still Submitted after Schedule 11's verify, so its Verified is still offered: the
    // client rule is admin && statusCode === 'S', and the sweep still says S (AC 7c's data half).
    mockMvc
        .perform(sweep(813).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.schedules1To10.statusCode", is("S")))
        .andExpect(jsonPath("$.schedule11.statusCode", is("V")));
  }

  @Test
  @DisplayName("AC 2: 814 zero locations is vacuously MET -> 200, category '11' at V")
  void zeroLocations_vacuouslyMet() throws Exception {
    mockMvc
        .perform(verify11(814, 2021))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trackStatus", is("V")));

    assertThat(statusRow(814).get("MILL_SILVICULTUR_STATUS_CODE")).isEqualTo("V");
    assertThat(categoryEleven(814).get("CATEGORY_STATE_CODE")).isEqualTo("V");
  }

  @Test
  @DisplayName(
      "AC 7b: 815 (S/S) a 1-10 VERIFY commits and leaves silviculture S, category '11' and the"
          + " Schedule 11 location exactly as they were")
  void oneToTenVerify_leavesSchedule11Alone() throws Exception {
    Map<String, Object> before = statusRow(815);
    Map<String, Object> elevenBefore = categoryEleven(815);
    List<Map<String, Object>> locationsBefore = locations(815);
    List<Map<String, Object>> costsBefore = locationCosts(815);
    assertThat(before.get("MILL_SILVICULTUR_STATUS_CODE")).isEqualTo("S");

    mockMvc
        .perform(
            post("/api/v1/check-status/verify")
                .param("millId", "815")
                .param("year", "2021")
                .accept(MediaType.APPLICATION_JSON)
                .with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.message.text", is(ONE_TO_TEN_VERIFIED)));

    Map<String, Object> after = statusRow(815);
    assertThat(after.get("ILCR_MILL_REPORT_STATUS_CODE")).isEqualTo("V");
    assertThat(after.get("MILL_SILVICULTUR_STATUS_CODE"))
        .isEqualTo(before.get("MILL_SILVICULTUR_STATUS_CODE"))
        .isEqualTo("S");
    assertThat(categoryEleven(815)).isEqualTo(elevenBefore);
    assertThat(locations(815)).isEqualTo(locationsBefore);
    assertThat(locationCosts(815)).isEqualTo(costsBefore);
  }

  // --- AC 4: the same context guard as /verify
  // -----------------------------------------------------

  @Test
  @DisplayName("AC 4: missing millId -> 400 ERR-001 verbatim, trailing space included")
  void missingMillId_400() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("year", "2021").with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
  }

  @Test
  @DisplayName("AC 4: blank millId -> 400 ERR-001")
  void blankMillId_400() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("millId", " ").param("year", "2021").with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
  }

  @Test
  @DisplayName("AC 4: non-numeric year -> 400 ERR-001, never Spring's own 400")
  void nonNumericYear_400() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).param("millId", "807").param("year", "twenty21").with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", is(ERR_001)));
  }

  @Test
  @DisplayName("AC 4: unknown mill -> 404 with the Check Status not-found text")
  void unknownMill_404() throws Exception {
    mockMvc
        .perform(verify11(999999, 2021))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail", is(CHECK_STATUS_NOT_FOUND)));
  }

  @Test
  @DisplayName("AC 4: known mill, year with no status row -> 404 Check Status not-found")
  void absentYear_404() throws Exception {
    mockMvc
        .perform(verify11(807, 1999))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail", is(CHECK_STATUS_NOT_FOUND)));
  }

  @Test
  @DisplayName("AC 4: mill closed (CLS) for the year -> 409 ERR-002 verbatim, nothing written")
  void closedMill_409() throws Exception {
    String before = footprint(516);

    mockMvc
        .perform(verify11(516, 2021))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(ERR_002)));

    assertThat(footprint(516)).isEqualTo(before);
  }
}
