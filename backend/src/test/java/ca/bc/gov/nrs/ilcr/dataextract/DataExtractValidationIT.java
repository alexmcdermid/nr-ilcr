package ca.bc.gov.nrs.ilcr.dataextract;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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
 * Acceptance tests for the Data Extract selection gate (UC-EXT-001, S09–S13).
 *
 * <p>The defining behaviour is ACCUMULATION: every failing check is reported on the SAME submit,
 * never first-failure-wins. Assertions therefore use Hamcrest {@code contains(...)} on {@code
 * messages[*].text} so both the exact SET and its ORDER are pinned — {@code hasItems} would pass a
 * response that dropped the accumulation and reported only one.
 *
 * <p>Message texts below are the verbatim legacy bundle strings; the required-field ones are the
 * JSF framework template resolved with the legacy {@code label} attributes ("Start Year", "End
 * Year"), not the visible {@code p:outputLabel} text, which carries a trailing space.
 *
 * <p>Fixtures: the existing snapshot seeds reporting periods 2021 (V2) and 2020 (V8) as the only
 * opened years. The endpoint validates mill SELECTION, never mill existence, so no mill fixture is
 * involved and no new migration is claimed.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Data Extract selection — POST /api/v1/reports/data-extract")
class DataExtractValidationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/reports/data-extract";

  private static final String START_REQUIRED = "Start Year: Value is required.";
  private static final String END_REQUIRED = "End Year: Value is required.";
  private static final String MILLS_NOT_SELECTED =
      "Please select at least one Mill for extracting.";
  private static final String SCHEDULES_NOT_SELECTED =
      "Please select at least one Schedule for extracting.";
  private static final String YEAR_RANGE =
      "The end reporting year must be greater or equal to start year.";
  private static final String CSV_UTF8 = "application/csv;charset=UTF-8";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  private static final RequestPostProcessor ADMIN =
      jwt()
          .jwt(
              j ->
                  j.claim("identity_provider", "azureidir")
                      .claim("client_roles", List.of("ILCR_ADMIN")))
          .authorities(j -> CONVERTER.convert(j).getAuthorities());

  @MockitoBean private JwtDecoder jwtDecoder;

  /**
   * A request body with every field supplied. Tests blank ONE field at a time so each message is
   * attributable to the field it names; passing {@code null} for a year omits it entirely, which
   * must resolve to the same required message as a blank string.
   */
  private static String body(String startYear, String endYear, String millIds, String schedules) {
    return """
        {"startYear":%s,"endYear":%s,"millIds":%s,"schedules":%s}
        """
        .formatted(json(startYear), json(endYear), millIds, schedules);
  }

  private static String json(String value) {
    return value == null ? "null" : "\"" + value + "\"";
  }

  private static final String ONE_MILL = "[514]";
  private static final String ONE_SCHEDULE = "[\"Schedule 1\"]";

  private org.springframework.test.web.servlet.ResultActions submit(String payload)
      throws Exception {
    return mockMvc.perform(
        post(ENDPOINT)
            .with(ADMIN)
            .contentType(MediaType.APPLICATION_JSON)
            .content(payload)
            .accept(MediaType.APPLICATION_JSON));
  }

  @Test
  @DisplayName("blank Start Year alone — ONE message, the verbatim required text (S09)")
  void blankStartYear_returnsOneMessage() throws Exception {
    submit(body(null, "2021", ONE_MILL, ONE_SCHEDULE))
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
        .andExpect(jsonPath("$.detail", containsString(START_REQUIRED)))
        // Exactly one — the positive control for every accumulation assertion below: the endpoint
        // reports what failed and nothing else.
        .andExpect(jsonPath("$.messages[*].text", contains(START_REQUIRED)));
  }

  @Test
  @DisplayName("blank End Year alone — ONE message, the verbatim required text (S10)")
  void blankEndYear_returnsOneMessage() throws Exception {
    submit(body("2020", null, ONE_MILL, ONE_SCHEDULE))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.messages[*].text", contains(END_REQUIRED)));
  }

  @Test
  @DisplayName("both years blank — TWO messages together, in screen order (Start then End)")
  void bothYearsBlank_returnsBothInScreenOrder() throws Exception {
    submit(body(null, null, ONE_MILL, ONE_SCHEDULE))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", containsString(START_REQUIRED)))
        .andExpect(jsonPath("$.detail", containsString(END_REQUIRED)))
        .andExpect(jsonPath("$.messages[*].text", contains(START_REQUIRED, END_REQUIRED)));
  }

  @Test
  @DisplayName("no mill selected — the verbatim ERR-002 text legacy could never reach (S11)")
  void noMill_returnsVerbatimMillsNotSelected() throws Exception {
    submit(body("2020", "2021", "[]", ONE_SCHEDULE))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.messages[0].key", org.hamcrest.Matchers.is("extractMillsNotSelectedMsg")))
        .andExpect(jsonPath("$.messages[*].text", contains(MILLS_NOT_SELECTED)));
  }

  @Test
  @DisplayName("millIds omitted entirely is the same refusal as an empty list")
  void millsOmitted_returnsVerbatimMillsNotSelected() throws Exception {
    submit("{\"startYear\":\"2020\",\"endYear\":\"2021\",\"schedules\":[\"Schedule 1\"]}")
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.messages[*].text", contains(MILLS_NOT_SELECTED)));
  }

  @Test
  @DisplayName("no schedule selected — the verbatim ERR-003 text legacy could never reach (S12)")
  void noSchedule_returnsVerbatimSchedulesNotSelected() throws Exception {
    submit(body("2020", "2021", ONE_MILL, "[]"))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath(
                "$.messages[0].key", org.hamcrest.Matchers.is("extractSchedulesNotSelectedMsg")))
        .andExpect(jsonPath("$.messages[*].text", contains(SCHEDULES_NOT_SELECTED)));
  }

  @Test
  @DisplayName("end year before start year — the verbatim ERR-001 text (S13)")
  void endBeforeStart_returnsVerbatimRangeMessage() throws Exception {
    submit(body("2021", "2020", ONE_MILL, ONE_SCHEDULE))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath(
                "$.messages[0].key", org.hamcrest.Matchers.is("extractReportingYearsNotMetMsg")))
        .andExpect(jsonPath("$.messages[*].text", contains(YEAR_RANGE)));
  }

  @Test
  @DisplayName("start == end is ACCEPTED — a single-year extract, never a range error")
  void startEqualsEnd_isAccepted() throws Exception {
    // Legacy rejects only start > end (ExtractDataMB.java:231), so a one-year extract is valid.
    // The CSV's content is pinned by DataExtractCsvIT; here only the acceptance and the title
    // block's year lines are asserted.
    submit(body("2021", "2021", ONE_MILL, ONE_SCHEDULE))
        .andExpect(status().isOk())
        .andExpect(content().contentType(CSV_UTF8))
        .andExpect(content().string(containsString("\"Start Year: 2021\"\n\"End Year: 2021\"\n")));
  }

  @Test
  @DisplayName("a fully valid multi-year selection is accepted and downloads as an attachment")
  void validSelection_isNotRejected() throws Exception {
    submit(body("2020", "2021", "[514,516]", "[\"Schedule 1\",\"Schedule 7\"]"))
        .andExpect(status().isOk())
        .andExpect(content().contentType(CSV_UTF8))
        .andExpect(
            header()
                .string(
                    "Content-Disposition",
                    matchesPattern("attachment; filename=\"dataExtract\\d{8}\\.csv\"")))
        .andExpect(header().exists("Content-Length"))
        .andExpect(content().string(containsString("\"**** End ****\"\n")));
  }

  @Test
  @DisplayName("an EMPTY-STRING year — what the page sends after Clear — is the required message")
  void emptyStringYear_isRequired() throws Exception {
    // The frontend pins `startYear: ''` on the wire for a cleared picker (DataExtract.test.tsx),
    // and
    // until this test no backend fixture ever sent that exact value — only null, omitted, or
    // non-numeric (21.1 review P9).
    submit(body("", "", ONE_MILL, ONE_SCHEDULE))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.messages[*].text", contains(START_REQUIRED, END_REQUIRED)));
  }

  @Test
  @DisplayName("an all-digit year too large for an int is 'not an open period', never 'required'")
  void overflowYear_isNotOpenRatherThanRequired() throws Exception {
    // ReportYearGuard's ruling for the single-year report endpoints, applied here too (21.1 review
    // P6): a number the caller demonstrably typed is a bad selection, not a missing one. It passes
    // the accumulating gate and is refused by the openness guard after it.
    submit(body("99999999999", "2021", ONE_MILL, ONE_SCHEDULE))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.detail", containsString("Report Year is not an open reporting period.")))
        .andExpect(jsonPath("$.detail", org.hamcrest.Matchers.not(containsString(START_REQUIRED))));
  }

  @Test
  @DisplayName(
      "every reachable failure accumulates on ONE submit, in screen order (S09-S12, AC6 post-Clear)")
  void allReachableFailures_accumulateInScreenOrder() throws Exception {
    // The post-Clear submit of AC6: all four pickers empty. FOUR messages, not legacy's three —
    // legacy skipped the Schedules required check because its input lacked immediate="true", so
    // PROCESS_VALIDATIONS never evaluated it (recorded deviation (B)).
    //
    // This is the MAXIMUM accumulation the checks allow: the range check needs two parseable years,
    // so it is mutually exclusive with the two blank-year checks and can never join them.
    submit(body(null, null, "[]", "[]"))
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
        .andExpect(
            jsonPath(
                "$.messages[*].text",
                contains(START_REQUIRED, END_REQUIRED, MILLS_NOT_SELECTED, SCHEDULES_NOT_SELECTED)))
        // `detail` is the "; "-joined text of the same four, so it proves the joined half of the
        // contract rather than restating the array.
        .andExpect(jsonPath("$.detail", containsString(START_REQUIRED)))
        .andExpect(jsonPath("$.detail", containsString(SCHEDULES_NOT_SELECTED)));
  }

  @Test
  @DisplayName("the range failure accumulates with both not-selected failures, range last")
  void rangeAndNotSelected_accumulateWithRangeLast() throws Exception {
    // The other maximal shape: years present but inverted, nothing else selected. Screen order puts
    // the two picker refusals before the cross-field range check.
    submit(body("2021", "2020", "[]", "[]"))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath(
                "$.messages[*].text",
                contains(MILLS_NOT_SELECTED, SCHEDULES_NOT_SELECTED, YEAR_RANGE)));
  }

  @Test
  @DisplayName("a non-numeric year returns the verbatim required message, NOT a framework 400")
  void nonNumericYear_returnsRequiredMessageNotFrameworkError() throws Exception {
    // The reason startYear/endYear are raw Strings on the request record. A typed component or a
    // @NotNull constraint makes Jackson/Spring reject first, producing a 400 whose detail is a
    // framework message and whose `messages` array is ABSENT — which silently destroys AC5.
    submit(body("not-a-year", "2021", ONE_MILL, ONE_SCHEDULE))
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
        .andExpect(jsonPath("$.messages[*].text", contains(START_REQUIRED)));
  }

  @Test
  @DisplayName("a non-numeric year still accumulates with the other picker failures")
  void nonNumericYear_stillAccumulates() throws Exception {
    submit(body("not-a-year", null, "[]", ONE_SCHEDULE))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath(
                "$.messages[*].text", contains(START_REQUIRED, END_REQUIRED, MILLS_NOT_SELECTED)));
  }

  @Test
  @DisplayName("a blank-string schedule entry does not count as a selection")
  void blankScheduleEntry_isNotASelection() throws Exception {
    // Defensive: a list holding only empty strings is nothing selected. Without this a client bug
    // would pass the gate with no schedule and reach the generator with an unusable selection.
    submit(body("2020", "2021", ONE_MILL, "[\"\",\"  \"]"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.messages[*].text", contains(SCHEDULES_NOT_SELECTED)));
  }

  @Test
  @DisplayName("no file is produced on a validation failure")
  void failure_producesNoFile() throws Exception {
    submit(body(null, null, "[]", "[]"))
        .andExpect(status().isBadRequest())
        // problem+json, never a CSV body or a download disposition.
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
        .andExpect(header().doesNotExist("Content-Disposition"));
  }

  @Test
  @DisplayName("a syntactically valid year that is not an opened period is refused after the gate")
  void yearNotOpen_isRefusedOnceTheGatePasses() throws Exception {
    // Unreachable from the UI (both pickers list only opened years) and deliberately NOT part of
    // the
    // accumulating gate: it runs only once all of AC5's checks pass, so it can never displace one
    // of
    // their messages. Reuses the shipped report-year guard and its existing text rather than
    // authoring a new refusal.
    submit(body("1999", "1999", ONE_MILL, ONE_SCHEDULE))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.detail", containsString("Report Year is not an open reporting period.")))
        // A single BusinessException, so NO `messages` array — the frontend's fallback-to-`detail`
        // path is what renders this one. Pinned so a later change to how BusinessException renders
        // cannot silently alter which frontend branch fires (21.1 review P8).
        .andExpect(jsonPath("$.messages").doesNotExist());
  }
}
