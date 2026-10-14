package ca.bc.gov.nrs.ilcr.checkstatus;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * What the two Schedule 11 reversal ITs share: the acting admin's token, the requests, and the
 * by-key reads their before/after assertions compare.
 *
 * <p>Security ON with a token converted through the production converter, so the audit name comes
 * from {@code custom:idp_username} and the directory GUID from {@code custom:idp_user_id} (the 17.1
 * trap). Neither reversal writes an identity pair, so the GUID matters here only as the thing a
 * legacy-style LICENSEE write would have recorded: {@code R__62} xrefs this admin to mill 824,
 * whose seeded LICENSEE pair names someone else.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
abstract class Schedule11ReversalSupport extends AbstractOracleIT {

  static final String SET_TO_DRAFT_11 = "/api/v1/check-status/schedule11/set-to-draft";
  static final String SET_TO_SUBMIT_11 = "/api/v1/check-status/schedule11/set-to-submit";
  static final String PROBLEM_JSON = "application/problem+json";

  static final String DRAFT_TEXT = "Schedule 11 has been set back to draft.";
  static final String SUBMITTED_TEXT = "Schedule 11 has been successfully submitted.";
  static final String NOT_SUBMITTED =
      "The report cannot be submitted. One or more of the Schedules have not passed validation."
          + " Please review and correct any errors.";
  static final String SUBMISSION_ERROR =
      "An error has been found submitting schedules. The error details have been logged. Please"
          + " contact ILCR application support.";
  static final String ERR_001 = "Please Select Mill and Reporting Year in the Home Page. ";
  static final String CHECK_STATUS_NOT_FOUND =
      "One or more of the schedules for the report have not been found.";
  static final String ERR_002 =
      "This Mill is not active for the current Reporting Year. "
          + "Please select another mill from the Home Page.";

  /** {@code R__62}'s acting admin, cross-referenced to mill 824 only. */
  static final String ADMIN_GUID = "REVERSE11ADMIN00011112222333AAA1";

  /** The licensee {@code R__62} records on 823 and 824. */
  static final String LICENSEE_GUID = "REVERSE11LICENSEE0001111222AAA11";

  /** The auditor {@code R__62} records on 823 and 824. */
  static final String AUDITOR_GUID = "REVERSE11AUDITOR000111122223AAA1";

  /** The audit name, from {@code custom:idp_username} (30-char column). */
  static final String ACTING_USER = "reverse11admin";

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
  @Autowired JdbcTemplate jdbc;

  static RequestPostProcessor admin() {
    Jwt token =
        Jwt.withTokenValue("reverse11-it-token")
            .header("alg", "none")
            .subject("26262626-5555-4444-5555-666666666666")
            .claim("idir_user_guid", ADMIN_GUID)
            .claim("idir_username", ACTING_USER)
            .claim("identity_provider", "azureidir")
            .claim("client_roles", List.of("ILCR_ADMIN"))
            .build();
    return authentication(CONVERTER.convert(token));
  }

  static MockHttpServletRequestBuilder reverse(String endpoint, long mill, int year) {
    return post(endpoint)
        .param("millId", String.valueOf(mill))
        .param("year", String.valueOf(year))
        .accept(MediaType.APPLICATION_JSON)
        .with(admin());
  }

  static MockHttpServletRequestBuilder sweep(long mill) {
    return get("/api/v1/check-status")
        .param("millId", String.valueOf(mill))
        .param("year", "2021")
        .accept(MediaType.APPLICATION_JSON);
  }

  static MockHttpServletRequestBuilder schedule11Page(long mill) {
    return get("/api/v1/schedule11")
        .param("millId", String.valueOf(mill))
        .param("year", "2021")
        .accept(MediaType.APPLICATION_JSON);
  }

  /** Per table the row count, revision sum and latest touch, plus the mill's own rows. */
  String footprint(long mill) {
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

  Map<String, Object> statusRow(long mill) {
    return jdbc.queryForMap(
        "SELECT ILCR_MILL_REPORT_STATUS_CODE, MILL_SILVICULTUR_STATUS_CODE, REPORT_COMPLETED_IND,"
            + " LICENSEE_MILL_ID, LICENSEE_USER_GUID, AUDITOR_MILL_ID, AUDITOR_USER_GUID,"
            + " REVISION_COUNT, UPDATE_USERID, UPDATE_TIMESTAMP, ENTRY_TIMESTAMP"
            + " FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        mill);
  }

  /** The four identity columns, which no reversal on either track may write. */
  Map<String, Object> identityPairs(long mill) {
    return jdbc.queryForMap(
        "SELECT LICENSEE_MILL_ID, LICENSEE_USER_GUID, AUDITOR_MILL_ID, AUDITOR_USER_GUID"
            + " FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        mill);
  }

  List<Map<String, Object>> categoryRows(long mill) {
    return jdbc.queryForList(
        "SELECT ILCR_CATEGORY_ID, CATEGORY_STATE_CODE, REVISION_COUNT, UPDATE_USERID,"
            + " UPDATE_TIMESTAMP FROM THE.ILCR_REPORT_CATEGORY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021 ORDER BY TO_NUMBER(ILCR_CATEGORY_ID)",
        mill);
  }

  /** Categories '1'..'10' only — everything a Schedule 11 transition must never write. */
  List<Map<String, Object>> oneToTenCategories(long mill) {
    return categoryRows(mill).stream()
        .filter(r -> !"11".equals(r.get("ILCR_CATEGORY_ID")))
        .toList();
  }

  Map<String, Object> categoryEleven(long mill) {
    return categoryRows(mill).stream()
        .filter(r -> "11".equals(r.get("ILCR_CATEGORY_ID")))
        .findFirst()
        .orElseThrow();
  }

  List<Map<String, Object>> locations(long mill) {
    return jdbc.queryForList(
        "SELECT BASIC_SILVICULTURE_REPORT_ID, REVISION_COUNT, UPDATE_USERID, UPDATE_TIMESTAMP"
            + " FROM THE.BASIC_SILVICULTURE_REPORT WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021"
            + " ORDER BY BASIC_SILVICULTURE_REPORT_ID",
        mill);
  }

  List<Map<String, Object>> locationCosts(long mill) {
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
  Map<String, Object> auditColumns(String table, String idColumn, long id) {
    return jdbc.queryForMap(
        "SELECT REVISION_COUNT, UPDATE_USERID, UPDATE_TIMESTAMP FROM THE."
            + table
            + " WHERE "
            + idColumn
            + " = ?",
        id);
  }
}
