package ca.bc.gov.nrs.ilcr.reportingyear;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test — Story 24.1 (UC-RY-001) Open Reporting Year, security ON. Exercises the real
 * cognito:groups → role → action path: {@code OPEN_REPORTING_YEAR} is ADMIN-only, so an {@code
 * ILCR_SUBMITTER} is denied 403 (S13). The recurring open path is driven against the shared seed (a
 * year already exists), proving an ACTIVE mill (990) gets a Draft/Draft report-status row for the
 * new year and a CLOSED mill (991) does not. It also proves an ACTIVE mill (992) without a
 * current-year status row is excluded, matching the legacy recurring-year query. Each test removes
 * the year it opened in {@link #cleanUp()} so the JVM-wide container stays at its seeded baseline
 * for other IT classes.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("/api/v1/admin/reporting-years — Open Reporting Year (admin-gated, Story 24.1)")
class ReportingYearIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/admin/reporting-years";
  private static final long ACTIVE_MILL = 990L;
  private static final long CLOSED_MILL = 991L;
  private static final long ACTIVE_MILL_WITHOUT_CURRENT_STATUS = 992L;
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  @Autowired private NamedParameterJdbcTemplate jdbc;

  private Integer openedYear;
  private Integer seededPeriodYear;

  @AfterEach
  void cleanUp() {
    if (openedYear != null) {
      MapSqlParameterSource p = new MapSqlParameterSource("year", openedYear);
      jdbc.update("DELETE FROM THE.ILCR_REPORT_CATEGORY WHERE REPORT_YEAR = :year", p);
      jdbc.update("DELETE FROM THE.ILCR_MILL_REPORT_STATUS WHERE REPORT_YEAR = :year", p);
      jdbc.update("DELETE FROM THE.ILCR_REPORTING_PERIOD WHERE REPORT_YEAR = :year", p);
      openedYear = null;
    }
    if (seededPeriodYear != null) {
      jdbc.update(
          "DELETE FROM THE.ILCR_MILL_REPORT_STATUS WHERE REPORT_YEAR = :year",
          new MapSqlParameterSource("year", seededPeriodYear));
      jdbc.update(
          "DELETE FROM THE.ILCR_REPORTING_PERIOD WHERE REPORT_YEAR = :year",
          new MapSqlParameterSource("year", seededPeriodYear));
      seededPeriodYear = null;
    }
  }

  private RequestPostProcessor groups(String... groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", List.of(groups)))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private int currentMaxYear() {
    Integer max =
        jdbc.queryForObject(
            "SELECT MAX(REPORT_YEAR) FROM THE.ILCR_REPORTING_PERIOD",
            new MapSqlParameterSource(),
            Integer.class);
    return max == null ? 0 : max;
  }

  private long statusRowCount(long millId, int year) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID = :m AND REPORT_YEAR = :y",
            new MapSqlParameterSource(Map.of("m", millId, "y", year)),
            Integer.class);
    return count == null ? 0 : count;
  }

  @Test
  @DisplayName(
      "admin opens the next year — 200, active mill initialized Draft, closed mill skipped")
  void admin_opensNextYear() throws Exception {
    // Seed a high reporting period so the recurring path (max + 1) targets a year no other fixture
    // touches — the accumulated seeds hold orphan status rows for lower years that would otherwise
    // collide on the PK. Removed in cleanUp() so the shared container stays at its baseline.
    seededPeriodYear = 3000;
    jdbc.update(
        "INSERT INTO THE.ILCR_REPORTING_PERIOD (REPORT_YEAR, ENTRY_USERID) VALUES (:year, 'SEED')",
        new MapSqlParameterSource("year", seededPeriodYear));
    jdbc.update(
        "INSERT INTO THE.ILCR_MILL_REPORT_STATUS "
            + "(REPORT_YEAR, ILCR_MILL_ID, ILCR_MILL_REPORT_STATUS_CODE, "
            + "MILL_SILVICULTUR_STATUS_CODE, REPORT_COMPLETED_IND, ENTRY_USERID, UPDATE_USERID) "
            + "VALUES (:year, :mill, 'D', 'D', 'N', 'SEED', 'SEED')",
        new MapSqlParameterSource(Map.of("year", seededPeriodYear, "mill", ACTIVE_MILL)));
    int expected = currentMaxYear() + 1;
    openedYear = expected;

    mockMvc
        .perform(post(ENDPOINT).with(groups("ILCR_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.year").value(expected))
        .andExpect(
            jsonPath("$.message")
                .value("The new reporting year " + expected + " has been successfully created."));

    // The period row exists (year selectable on Home) with the audit quartet populated — a missing
    // stamp would be NULL here and fail, catching the delivery NOT NULL before deployment.
    Map<String, Object> period =
        jdbc.queryForMap(
            "SELECT ENTRY_USERID, ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP "
                + "FROM THE.ILCR_REPORTING_PERIOD WHERE REPORT_YEAR = :y",
            new MapSqlParameterSource("y", expected));
    assertThat(period.get("ENTRY_USERID")).isNotNull();
    assertThat(period.get("ENTRY_TIMESTAMP")).isNotNull();
    assertThat(period.get("UPDATE_USERID")).isNotNull();
    assertThat(period.get("UPDATE_TIMESTAMP")).isNotNull();

    // Active mill with a current-year status got a both-tracks-Draft, not-completed row; closed and
    // active-but-not-present-in-the-current-year status set mills got none.
    assertThat(statusRowCount(ACTIVE_MILL, expected)).isEqualTo(1);
    assertThat(statusRowCount(CLOSED_MILL, expected)).isZero();
    assertThat(statusRowCount(ACTIVE_MILL_WITHOUT_CURRENT_STATUS, expected)).isZero();
    Map<String, Object> row =
        jdbc.queryForMap(
            "SELECT ILCR_MILL_REPORT_STATUS_CODE, MILL_SILVICULTUR_STATUS_CODE, REPORT_COMPLETED_IND, "
                + "ENTRY_USERID, UPDATE_USERID FROM THE.ILCR_MILL_REPORT_STATUS "
                + "WHERE ILCR_MILL_ID = :m AND REPORT_YEAR = :y",
            new MapSqlParameterSource(Map.of("m", ACTIVE_MILL, "y", expected)));
    assertThat(row.get("ILCR_MILL_REPORT_STATUS_CODE")).isEqualTo("D");
    assertThat(row.get("MILL_SILVICULTUR_STATUS_CODE")).isEqualTo("D");
    assertThat(row.get("REPORT_COMPLETED_IND")).isEqualTo("N");
    // Audit quartet populated (delivery NOT NULL) — a dropped stamp fails here, not in production.
    assertThat(row.get("ENTRY_USERID")).isNotNull();
    assertThat(row.get("UPDATE_USERID")).isNotNull();

    // Active mill gets one per-category record per schedule category (Draft, reportable-detail Y);
    // closed and active-but-not-present-in-the-current-year status set mills get none.
    assertThat(categoryRowCount(ACTIVE_MILL, expected)).isEqualTo(11);
    assertThat(categoryRowCount(CLOSED_MILL, expected)).isZero();
    assertThat(categoryRowCount(ACTIVE_MILL_WITHOUT_CURRENT_STATUS, expected)).isZero();
    Map<String, Object> cat =
        jdbc.queryForMap(
            "SELECT CATEGORY_STATE_CODE, REPORTABLE_DETAIL_IND FROM THE.ILCR_REPORT_CATEGORY "
                + "WHERE ILCR_MILL_ID = :m AND REPORT_YEAR = :y AND ILCR_CATEGORY_ID = '1'",
            new MapSqlParameterSource(Map.of("m", ACTIVE_MILL, "y", expected)));
    assertThat(cat.get("CATEGORY_STATE_CODE")).isEqualTo("D");
    assertThat(cat.get("REPORTABLE_DETAIL_IND")).isEqualTo("Y");
  }

  private long categoryRowCount(long millId, int year) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM THE.ILCR_REPORT_CATEGORY WHERE ILCR_MILL_ID = :m AND REPORT_YEAR = :y",
            new MapSqlParameterSource(Map.of("m", millId, "y", year)),
            Integer.class);
    return count == null ? 0 : count;
  }

  @Test
  @DisplayName("admin view reports the recurring next year")
  void admin_viewShowsNextYear() throws Exception {
    int expectedNext = currentMaxYear() + 1;
    mockMvc
        .perform(get(ENDPOINT).with(groups("ILCR_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.firstTime").value(false))
        .andExpect(jsonPath("$.nextYear").value(expectedNext));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER is denied open — 403 (S13, admin-only action)")
  void submitter_isForbidden() throws Exception {
    mockMvc
        .perform(post(ENDPOINT).with(groups("ILCR_SUBMITTER")))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no ILCR group is denied — 403")
  void noGroup_isForbidden() throws Exception {
    mockMvc.perform(get(ENDPOINT).with(groups())).andExpect(status().isForbidden());
  }
}
