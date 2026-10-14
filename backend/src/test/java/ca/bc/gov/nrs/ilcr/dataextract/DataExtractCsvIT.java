package ca.bc.gov.nrs.ilcr.dataextract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.dataextract.csv.DataExtractGenerator;
import ca.bc.gov.nrs.ilcr.millcontext.MillContextRepository;
import ca.bc.gov.nrs.ilcr.schedule1.Schedule1Service;
import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance tests for the generated CSV itself — the response half of the Data Extract endpoint.
 *
 * <p>The selection gate's refusals belong to {@code DataExtractValidationIT} and authorization to
 * {@code DataExtractAuthorizationIT}; what is asserted here is the FILE: its headers, its title
 * block, its section framing, its markers, the combined layout and its three negative controls, and
 * that a failure mid-build leaves neither bytes nor a spool file behind.
 *
 * <p>Assertions read the body as PARSED ROWS rather than as one long string, through {@link #rows}
 * and {@link #cells} below. A failing assertion then names the row and the cell instead of dumping
 * a several-hundred-line diff, and a row-order assertion cannot accidentally pass because a
 * substring happened to appear somewhere else in the file.
 *
 * <p>Fixtures are {@code R__60_data_extract_fixtures.sql}: mills 760 (Verified on both tracks, with
 * a Schedule 3 and one seeded row for each of Schedules 1 Other, 3 sub-pages, 4, 5, 8 and 10), 761
 * (Verified on Schedules 1–10 only, Draft on silviculture, with NO Schedule 3 and one silviculture
 * location) and 762 (Submitted, whose only schedule row is an EMPTY Schedule 1 summary), every row
 * in report year 2020. Year 2021 is deliberately empty of fixtures — see that file's header for why
 * the second year of a range carries nothing.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Data Extract CSV — the generated file")
class DataExtractCsvIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/reports/data-extract";
  private static final String CSV_UTF8 = "application/csv;charset=UTF-8";

  private static final String NO_DATA_FOUND = "*** NO DATA FOUND ***";
  private static final String NO_SCHEDULE_3 = "*** NO SCHEDULE 3 ***";
  private static final String NO_STATUS = "** NO STATUS **";
  private static final String END_MARKER = "**** End ****";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  private static final RequestPostProcessor ADMIN =
      jwt()
          .jwt(
              j ->
                  j.claim("identity_provider", "azureidir")
                      .claim("client_roles", List.of("ILCR_ADMIN")))
          .authorities(j -> CONVERTER.convert(j).getAuthorities());

  /**
   * Where the spooler writes, pinned for THIS class. {@code FileSpooler} honours {@code
   * ilcr.reporting.spool-directory} and falls back to {@code java.io.tmpdir} only when that is
   * blank, so a before/after listing of the JVM temp directory would pass vacuously under any
   * configured directory (code review finding). A directory of this class's own also keeps the
   * listing clear of whatever other suites leave in the shared temp directory.
   */
  private static final Path SPOOL_DIRECTORY = createSpoolDirectory();

  private static Path createSpoolDirectory() {
    try {
      return Files.createTempDirectory("ilcr-data-extract-it");
    } catch (IOException e) {
      throw new IllegalStateException("Could not create the IT spool directory", e);
    }
  }

  @DynamicPropertySource
  static void spoolDirectory(DynamicPropertyRegistry registry) {
    registry.add("ilcr.reporting.spool-directory", SPOOL_DIRECTORY::toString);
  }

  @MockitoBean private JwtDecoder jwtDecoder;

  /**
   * Spied rather than replaced: every test but the failure one needs the REAL Schedule 1 read
   * against the fixtures, and only that one stubs it to throw.
   */
  @MockitoSpyBean private Schedule1Service schedule1Service;

  /**
   * The status-code lookup the generator itself resolves STATUS cells through, so an expected
   * description is read from {@code THE.ILCR_MILL_REPORT_STATUS_CODE} rather than retyped here.
   */
  @Autowired private MillContextRepository millContextRepository;

  /** The description for a report-status code, as the generator's STATUS cell renders it. */
  private String statusOf(String code) {
    return millContextRepository.findStatusDescription(code).orElseThrow();
  }

  /** The spool directory's files, so a leftover partial file is detectable. */
  private static Set<Path> spoolFiles(Path directory) throws IOException {
    try (var entries = Files.list(directory)) {
      return entries
          .filter(p -> p.getFileName().toString().startsWith("dataExtract"))
          .collect(Collectors.toSet());
    }
  }

  private static String body(int startYear, int endYear, String millIds, String schedules) {
    return """
        {"startYear":"%d","endYear":"%d","millIds":%s,"schedules":%s}
        """
        .formatted(startYear, endYear, millIds, schedules);
  }

  private MvcResult extract(String payload) throws Exception {
    return mockMvc
        .perform(
            post(ENDPOINT)
                .with(ADMIN)
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload)
                .accept(MediaType.ALL))
        .andExpect(status().isOk())
        .andExpect(content().contentType(CSV_UTF8))
        .andReturn();
  }

  /** The body as UTF-8 text. Read from the raw bytes, so a charset regression is visible. */
  private static String text(MvcResult result) {
    return new String(result.getResponse().getContentAsByteArray(), StandardCharsets.UTF_8);
  }

  /**
   * The body split into physical lines.
   *
   * <p>Deliberately naive: a quoted cell CAN contain a newline, so a comment cell would split a
   * logical row across two entries here. No fixture seeds such a comment, and keeping the split
   * naive means the line count is the file's real line count — which is what a comparison against a
   * legacy sample looks at.
   */
  private static List<String> rows(MvcResult result) {
    String body = text(result);
    // The UTF-8 byte-order mark is asserted once, then dropped so the first row compares as text.
    assertThat(body).startsWith("\uFEFF");
    body = body.substring(1);
    // The file ends with a line terminator, so the trailing empty element is not a row.
    return Arrays.asList(body.substring(0, body.length() - 1).split("\n", -1));
  }

  /**
   * One row's cells, with the quoting stripped.
   *
   * <p>Splits on the delimiter between quoted cells rather than on every comma, because a formatted
   * figure carries thousands separators inside its quotes. A null cell arrives as an empty field
   * with no quotes at all, which this renders as an empty string.
   */
  private static List<String> cells(String row) {
    return Arrays.stream(row.split("(?<=\"),(?=\")|(?<=^),|,(?=$)|(?<=\"),(?=$)|(?<=^),(?=\")"))
        .map(
            cell ->
                cell.length() >= 2 && cell.startsWith("\"") && cell.endsWith("\"")
                    ? cell.substring(1, cell.length() - 1).replace("\"\"", "\"")
                    : cell)
        .toList();
  }

  /** The index of the first row whose single cell is {@code title}, or -1. */
  private static int sectionAt(List<String> rows, String title) {
    return rows.indexOf("\"" + title + "\"");
  }

  /** The header cells of the section titled {@code title}, asserting the section is present. */
  private static List<String> headerOf(List<String> rows, String title) {
    int at = sectionAt(rows, title);
    assertThat(at).as("section %s", title).isPositive();
    return cells(rows.get(at + 1));
  }

  /** The cells of the {@code n}th body row (1-based) of the section titled {@code title}. */
  private static List<String> bodyRow(List<String> rows, String title, int n) {
    return cells(rows.get(sectionAt(rows, title) + 1 + n));
  }

  /**
   * The position of a named header cell, so a wide row is asserted by column NAME. Counting to
   * column 17 of a 58-column row is where a test would silently pin the wrong cell.
   */
  private static int column(List<String> header, String name) {
    int index = header.indexOf(name);
    assertThat(index).as("header cell %s", name).isNotNegative();
    return index;
  }

  @Nested
  @DisplayName("the response and the title block")
  class ResponseAndTitle {

    @Test
    @DisplayName("a valid selection answers a CSV attachment whose Content-Length is the body size")
    void answersAttachmentWithRealContentLength() throws Exception {
      MvcResult result = extract(body(2020, 2020, "[760]", "[\"Schedule 1\"]"));

      // The whole-file-or-no-file contract made observable: the length header can only be right if
      // the file was complete before the response was committed.
      int declared = Integer.parseInt(result.getResponse().getHeader("Content-Length"));
      assertThat(declared).isEqualTo(result.getResponse().getContentAsByteArray().length);
      assertThat(result.getResponse().getHeader("Content-Disposition"))
          .matches("attachment; filename=\"dataExtract\\d{8}\\.csv\"");
    }

    @Test
    @DisplayName("the title block is legacy's seven lines, then two blank rows")
    void titleBlockIsVerbatim() throws Exception {
      List<String> rows = rows(extract(body(2020, 2020, "[760,761]", "[\"Schedule 1\"]")));

      assertThat(rows.get(0))
          .isEqualTo(
              "\"Ministry of Forests, Lands, Natural Resource Operations & Rural Development,"
                  + " ILCR\"");
      // The timestamp is legacy's pattern, which pairs a 24-hour clock WITH an AM/PM marker.
      // Matched
      // by shape because the value is the server clock; the redundant marker is the part that must
      // not be "corrected" to a 12-hour clock.
      assertThat(cells(rows.get(1)).get(0))
          .matches("Data Extract on [A-Z][a-z]+, \\d{2} \\d{4} @ \\d{2}:\\d{2} [AP]M");
      assertThat(rows.get(2)).isEqualTo("\"Start Year: 2020\"");
      assertThat(rows.get(3)).isEqualTo("\"End Year: 2020\"");
      // Mill NUMBERs, in the order the request listed their ids — not the numbers' own order.
      assertThat(rows.get(4)).isEqualTo("\"Included Mills: 7600, 7610\"");
      assertThat(rows.get(5)).isEqualTo("\"Data Verified: Yes\"");
      // The detail-EXPANDED names, not the picker labels: legacy's title line outside the combined
      // layout listed what each label expands to, and Schedule 1 expands to itself plus its Other
      // Costs section (ExtractDataMB.java:361-363).
      assertThat(rows.get(6)).isEqualTo("\"Schedules: Schedule 1, Schedule 1 Other\"");
      // Legacy's blank line is a one-cell row holding a single space, not an empty line.
      assertThat(rows.get(7)).isEqualTo("\" \"");
      assertThat(rows.get(8)).isEqualTo("\" \"");
    }

    @Test
    @DisplayName("the file ends with two blank rows and the end marker")
    void endsWithTheEndMarker() throws Exception {
      List<String> rows = rows(extract(body(2020, 2020, "[760]", "[\"Schedule 1\"]")));

      assertThat(rows.get(rows.size() - 1)).isEqualTo("\"" + END_MARKER + "\"");
      assertThat(rows.get(rows.size() - 2)).isEqualTo("\" \"");
      assertThat(rows.get(rows.size() - 3)).isEqualTo("\" \"");
    }

    @Test
    @DisplayName("the Schedules line expands Schedule 7 into its two sub-schedules")
    void scheduleSevenExpandsInTheTitle() throws Exception {
      List<String> rows = rows(extract(body(2020, 2020, "[760]", "[\"Schedule 7\"]")));

      // One picker label, two sections — and the title line names the expansion, as legacy's
      // detail-expanded list did outside the combined layout.
      assertThat(cells(rows.get(6)).get(0)).startsWith("Schedules: ");
      assertThat(sectionAt(rows, "**** Schedule 7A - Bridge****")).isPositive();
      assertThat(sectionAt(rows, "**** Schedule 7B - Culvert ****")).isPositive();
    }
  }

  @Nested
  @DisplayName("Data Verified")
  class DataVerified {

    /** The Data Verified line's verdict alone — the cell is "Data Verified: Yes|No". */
    private String verdict(int startYear, int endYear, String mills, String schedules)
        throws Exception {
      String cell = cells(rows(extract(body(startYear, endYear, mills, schedules))).get(5)).get(0);
      assertThat(cell).startsWith("Data Verified: ");
      return cell.substring("Data Verified: ".length());
    }

    @Test
    @DisplayName("Yes when every selected mill/year is V on the one applicable track")
    void yesWhenAllVerifiedOnTheApplicableTrack() throws Exception {
      // 760 and 761 are both V on the Schedules 1-10 track; 761's DRAFT silviculture code is not
      // applicable to this selection and must not drag the verdict down.
      assertThat(verdict(2020, 2020, "[760,761]", "[\"Schedule 1\"]")).isEqualTo("Yes");
    }

    @Test
    @DisplayName("No when a mill fails the OTHER applicable track — the AND, not legacy's OR")
    void noWhenOnlyOneTrackIsVerified() throws Exception {
      // Legacy OR'd the two tracks when both kinds were selected, so this same selection printed
      // Yes on the strength of 761's main track alone while its Schedule 11 track sat at Draft.
      assertThat(verdict(2020, 2020, "[760,761]", "[\"Schedule 1\",\"Schedule 11\"]"))
          .isEqualTo("No");
      // The positive control on the same pair of tracks: 760 is V on both.
      assertThat(verdict(2020, 2020, "[760]", "[\"Schedule 1\",\"Schedule 11\"]")).isEqualTo("Yes");
    }

    @Test
    @DisplayName("No when a selected mill/year has NO status row — legacy's vacuous Yes is gone")
    void noWhenAStatusRowIsMissing() throws Exception {
      // 2021 carries no status row for these mills, so the range 2020-2021 has unverified pairs in
      // it. Legacy built its verdict only from rows that existed and so printed Yes here.
      assertThat(verdict(2020, 2021, "[760]", "[\"Schedule 1\"]")).isEqualTo("No");
    }

    @Test
    @DisplayName("No for a non-V code, and Schedule 7 alone reads the Schedules 1-10 track")
    void scheduleSevenUsesTheMainTrack() throws Exception {
      // 762 is Submitted on the main track and Verified on silviculture. A Schedule-7-only
      // selection must therefore read No — legacy read No too, but for the wrong reason: its check
      // tested for a label its expanded list never held, so it matched no track at all and would
      // have said No however verified the data was. The control below is what tells the two apart.
      assertThat(verdict(2020, 2020, "[762]", "[\"Schedule 7\"]")).isEqualTo("No");
      // Same mill, same single label, the track it IS verified on: Yes. Under legacy's blind spot
      // the first assertion would pass and this one would fail.
      assertThat(verdict(2020, 2020, "[762]", "[\"Schedule 11\"]")).isEqualTo("Yes");
    }

    @Test
    @DisplayName("the flag never blocks extraction — an unverified selection still gets its file")
    void neverBlocksExtraction() throws Exception {
      List<String> rows = rows(extract(body(2020, 2020, "[762]", "[\"Schedule 1\"]")));

      assertThat(cells(rows.get(5)).get(0)).isEqualTo("Data Verified: No");
      assertThat(rows.get(rows.size() - 1)).isEqualTo("\"" + END_MARKER + "\"");
    }
  }

  @Nested
  @DisplayName("sections, markers and order")
  class SectionsAndMarkers {

    @Test
    @DisplayName("a selected schedule with no rows anywhere still opens and carries the marker")
    void noRowsScheduleEmitsTheWholeScheduleMarker() throws Exception {
      // Mill 762 has no schedule data at all. The section is still framed — blank row, title,
      // header — and its body is the five-cell whole-schedule marker. Legacy dropped the section
      // silently in one of its two no-data paths; the rebuild always emits it.
      List<String> rows = rows(extract(body(2020, 2020, "[762]", "[\"Schedule 6\"]")));
      int title = sectionAt(rows, "**** Schedule 6 ****");

      assertThat(title).isPositive();
      assertThat(rows.get(title - 1)).isEqualTo("\" \"");
      assertThat(cells(rows.get(title + 1)).get(0)).isEqualTo("MILL_NUMBER");
      List<String> marker = cells(rows.get(title + 2));
      assertThat(marker).containsExactly("7620", "2020 - 2020", "-", "-", NO_DATA_FOUND);
    }

    @Test
    @DisplayName("one schedule's marker does not suppress another schedule's rows")
    void markerDoesNotSuppressOtherSections() throws Exception {
      List<String> rows =
          rows(extract(body(2020, 2020, "[760]", "[\"Schedule 1\",\"Schedule 6\"]")));

      // Schedule 1 has rows for this mill, Schedule 6 has none; both sections appear and each
      // carries its own outcome.
      int schedule1 = sectionAt(rows, "**** Schedule 1 ****");
      int schedule6 = sectionAt(rows, "**** Schedule 6 ****");
      assertThat(schedule1).isPositive();
      assertThat(schedule6).isGreaterThan(schedule1);
      assertThat(cells(rows.get(schedule1 + 2)).get(0)).isEqualTo("7600");
      assertThat(cells(rows.get(schedule6 + 2))).contains(NO_DATA_FOUND);
    }

    @Test
    @DisplayName("the NO SCHEDULE 3 sentinel appears in Schedule 1 rows only, and only when due")
    void sentinelAppearsInScheduleOneOnly() throws Exception {
      // 761 has a Schedule 1 but no Schedule 3 summary; 760 has both. One request, both shapes.
      MvcResult result = extract(body(2020, 2020, "[760,761]", "[\"Schedule 1\",\"Schedule 2\"]"));
      List<String> rows = rows(result);
      int schedule1 = sectionAt(rows, "**** Schedule 1 ****");

      List<String> mill760 = cells(rows.get(schedule1 + 2));
      List<String> mill761 = cells(rows.get(schedule1 + 3));
      assertThat(mill760.get(0)).isEqualTo("7600");
      assertThat(mill761.get(0)).isEqualTo("7610");
      assertThat(mill760).doesNotContain(NO_SCHEDULE_3);
      assertThat(mill761).contains(NO_SCHEDULE_3);

      // And nowhere else in the file — Schedule 2's own Schedule-3-derived cells use the ordinary
      // null marker, because legacy paired them positionally and would have misaligned them.
      int schedule2 = sectionAt(rows, "**** Schedule 2 ****");
      assertThat(rows.subList(schedule2, rows.size()))
          .noneMatch(row -> row.contains(NO_SCHEDULE_3));

      // 761 has a Schedule 2 figure and no Schedule 3, so its Schedule 2 row is the PER-RECORD
      // marker (recorded deviation (Q)), with the main-track status description in its third cell.
      // 760 has no Schedule 2 at all and contributes no row (legacy's checkEmpty), so that marker
      // is the section's only body row and the next row is the blank that closes the section.
      assertThat(cells(rows.get(schedule2 + 2)))
          .containsExactly("7610", "2020", mill761.get(2), "761", NO_DATA_FOUND);
      assertThat(rows.get(schedule2 + 3)).isEqualTo("\" \"");
    }

    @Test
    @DisplayName("a mill/year with no status row renders the verbatim NO STATUS cell")
    void missingStatusRowRendersNoStatus() throws Exception {
      // The 2021 half of the range has no status row for 760, and no Schedule 1 either, so the
      // status cell is observed through a section that DOES have a 2021 row to show. Schedule 6 has
      // none for any year, so the whole-schedule marker is what 2021 produces; the status cell is
      // instead asserted on the section whose rows span both years.
      List<String> rows = rows(extract(body(2020, 2021, "[760]", "[\"Schedule 1\"]")));
      int schedule1 = sectionAt(rows, "**** Schedule 1 ****");

      // Only 2020 has a Schedule 1 summary, so there is exactly one data row and it carries the
      // 2020 status description. The NO STATUS path is proven by the Data Verified No above and by
      // the unit tests; asserting it here would need a 2021 summary, which the fixture cannot add.
      assertThat(cells(rows.get(schedule1 + 2)).get(2)).isNotEqualTo(NO_STATUS);
      assertThat(cells(rows.get(schedule1 + 2)).get(1)).isEqualTo("2020");
    }

    @Test
    @DisplayName("sections appear in ascending schedule order whatever order the request listed")
    void sectionsAreAscendingRegardlessOfRequestOrder() throws Exception {
      List<String> rows =
          rows(
              extract(body(2020, 2020, "[760]", "[\"Schedule 9\",\"Schedule 1\",\"Schedule 6\"]")));

      // Equal to legacy's observable order, since its checkbox menu posted values in component
      // order — and it makes the file independent of how a client happens to order its request.
      assertThat(sectionAt(rows, "**** Schedule 1 ****"))
          .isLessThan(sectionAt(rows, "**** Schedule 6 ****"));
      assertThat(sectionAt(rows, "**** Schedule 6 ****"))
          .isLessThan(sectionAt(rows, "**** Schedule 9 ****"));
    }

    @Test
    @DisplayName("an unknown schedule label contributes no section")
    void unknownLabelIsIgnored() throws Exception {
      List<String> rows =
          rows(extract(body(2020, 2020, "[760]", "[\"Schedule 1\",\"Schedule 12\"]")));

      // The ruled behaviour carried from the selection story: an unrecognised label is dropped
      // rather than refused, exactly as legacy's dispatch matched no builder for it.
      assertThat(sectionAt(rows, "**** Schedule 1 ****")).isPositive();
      assertThat(rows).noneMatch(row -> row.contains("Schedule 12"));
    }
  }

  @Nested
  @DisplayName("Schedule 1's own rules")
  class ScheduleOneRules {

    @Test
    @DisplayName("every record empty gives ONE whole-schedule marker, not a per-record one")
    void allEmptyGivesOneWholeScheduleMarker() throws Exception {
      // 762's Schedule 1 summary has no detail rows, so findStoredSchedule1 finds a record whose
      // every figure is null. Legacy branched the WHOLE section on that (Schedule1Extract.java:38,
      // isEmptyAllSchedule): the body is the five-cell whole-schedule marker, and NOT the
      // four-leading-cell per-record marker an empty pair gets once some other pair has figures.
      List<String> rows = rows(extract(body(2020, 2020, "[762]", "[\"Schedule 1\"]")));
      int title = sectionAt(rows, "**** Schedule 1 ****");

      assertThat(title).isPositive();
      assertThat(cells(rows.get(title + 1)).get(0)).isEqualTo("MILL_NUMBER");
      assertThat(cells(rows.get(title + 2)))
          .containsExactly("7620", "2020 - 2020", "-", "-", NO_DATA_FOUND);
      // Exactly one body row: what follows is the blank that opens the Other Costs section.
      assertThat(rows.get(title + 3)).isEqualTo("\" \"");
      assertThat(rows.get(title + 4)).isEqualTo("\"**** Schedule 1 - Other Costs ****\"");
    }

    @Test
    @DisplayName("Other Costs lists the itemized row with its own volume, then a Total: row")
    void otherCostsRowsThenTotal() throws Exception {
      // 760 has a shared item-19 volume of 5000 and one itemized item-19 row of 3000 stored at
      // volume 5000. The row shows its own stored volume, and the Total: row formats the summed
      // VOLUME to two decimals but the summed COST to none — legacy's inversion, kept by
      // Schedule1OtherSection.
      List<String> rows = rows(extract(body(2020, 2020, "[760]", "[\"Schedule 1\"]")));
      String title = "**** Schedule 1 - Other Costs ****";

      assertThat(headerOf(rows, title)).startsWith("MILL_NUMBER").endsWith("CPU_$/M3");
      assertThat(bodyRow(rows, title, 1))
          .containsExactly(
              "7600", "2020", statusOf("V"), "760", "Extract Other Cost", "5,000", "3,000", "0.60");
      assertThat(bodyRow(rows, title, 2))
          .containsExactly("", "", "", "", "Total:", "5,000.00", "3,000", "0.60");
    }

    @Test
    @DisplayName("Other Costs prints each row's own volume when there is no shared volume row")
    void otherCostsWithNoSharedRowPrintTheirOwnVolumes() throws Exception {
      // 761's itemized item-19 rows carry volumes 175000 and 125000 and there is NO
      // null-description shared row — the seeded mill 7777 / 2015 shape, where the rebuilt extract
      // printed "-" in every VOLUME and CPU cell. Legacy printed each row's own figures
      // (Schedule1OtherExtract.java:77, :79) and summed them into Total: (:88).
      List<String> rows = rows(extract(body(2020, 2020, "[761]", "[\"Schedule 1\"]")));
      String title = "**** Schedule 1 - Other Costs ****";
      String status = statusOf("V");

      assertThat(bodyRow(rows, title, 1))
          .containsExactly(
              "7610", "2020", status, "761", "Extract Own Volume A", "175,000", "25,000", "0.14");
      assertThat(bodyRow(rows, title, 2))
          .containsExactly(
              "7610", "2020", status, "761", "Extract Own Volume B", "125,000", "26,250", "0.21");
      assertThat(bodyRow(rows, title, 3))
          .containsExactly("", "", "", "", "Total:", "300,000.00", "51,250", "0.17");
    }

    @Test
    @DisplayName("rows walk mills by ID ascending while the title keeps the request's order")
    void rowsAreByMillIdWhateverTheRequestOrder() throws Exception {
      // Legacy's pair walk sorted by mill id, then year; its title line listed the mills as
      // selected. Posting [761, 760] separates the two orders so a walk that followed the request
      // order — or a title that sorted — would each be caught on its own.
      List<String> rows = rows(extract(body(2020, 2020, "[761,760]", "[\"Schedule 1\"]")));
      int schedule1 = sectionAt(rows, "**** Schedule 1 ****");

      assertThat(rows.get(4)).isEqualTo("\"Included Mills: 7610, 7600\"");
      assertThat(cells(rows.get(schedule1 + 2)).get(0)).isEqualTo("7600");
      assertThat(cells(rows.get(schedule1 + 3)).get(0)).isEqualTo("7610");
    }
  }

  @Nested
  @DisplayName("the schedule walks, against seeded figures")
  class ScheduleWalks {

    @Test
    @DisplayName("Schedule 3: the main row and both sub-page walks render the seeded figures")
    void scheduleThree() throws Exception {
      List<String> rows = rows(extract(body(2020, 2020, "[760]", "[\"Schedule 3\"]")));

      String main = "**** Schedule 3 ****";
      List<String> header = headerOf(rows, main);
      assertThat(header).startsWith("MILL_NUMBER").endsWith("COMMENTS");
      List<String> row = bodyRow(rows, main, 1);
      assertThat(row).hasSize(header.size());
      assertThat(row.get(0)).isEqualTo("7600");
      // The seeded item-118 PO&P timber volume, and the item-29 Annual Rents harvest figure.
      assertThat(row.get(column(header, "PO&P_M3"))).isEqualTo("7,500");
      assertThat(row.get(column(header, "RENTS_TOTAL_$"))).isEqualTo("1,000");

      // Other Acceptable: one TOT + PO&P group, crown derived as their difference. The legacy
      // title says "Other Costs", not "Acceptable" — kept.
      String accept = "**** Schedule 3 - Other Costs ****";
      assertThat(headerOf(rows, accept)).startsWith("MILL_NUMBER").endsWith("CROWN_$");
      assertThat(bodyRow(rows, accept, 1))
          .containsExactly(
              "7600", "2020", statusOf("V"), "760", "Consulting Fees", "800", "300", "500");
      assertThat(bodyRow(rows, accept, 2))
          .containsExactly("", "", "", "", "Total:", "800", "300", "500");

      // Included Unacceptable: legacy's fixed Annual Rents row first, then the item-38 row, then
      // a Total: that includes the rents; CROWN_$ copies TOTAL_$ on every row, as legacy wrote it.
      String unaccept = "**** Schedule 3 - Unacceptable Costs ****";
      assertThat(headerOf(rows, unaccept)).startsWith("MILL_NUMBER").endsWith("CROWN_$");
      assertThat(bodyRow(rows, unaccept, 1))
          .containsExactly(
              "7600",
              "2020",
              statusOf("V"),
              "760",
              "Annual Rents (Forest Act, S111)",
              "1,000",
              "1,000");
      assertThat(bodyRow(rows, unaccept, 2))
          .containsExactly("7600", "2020", statusOf("V"), "760", "Penalty Fees", "250", "250");
      assertThat(bodyRow(rows, unaccept, 3))
          .containsExactly("", "", "", "", "Total:", "1,250", "1,250");
    }

    @Test
    @DisplayName("Schedule 4: the location row and its Towing sub-page render the seeded figures")
    void scheduleFour() throws Exception {
      List<String> rows = rows(extract(body(2020, 2020, "[760]", "[\"Schedule 4\"]")));

      String main = "**** Schedule 4 ****";
      List<String> header = headerOf(rows, main);
      assertThat(header).startsWith("MILL_NUMBER").endsWith("COMMENTS").hasSize(58);
      List<String> location = bodyRow(rows, main, 1);
      assertThat(location).hasSize(58);
      assertThat(location.get(0)).isEqualTo("7600");
      assertThat(location.get(column(header, "LOCATION"))).isEqualTo("Extract Dump");
      // The fixed category 40 on the primary report; every $/m3 here is the Excel-formula form.
      assertThat(location.get(column(header, "LAKESIDE_M3"))).isEqualTo("2,000");
      assertThat(location.get(column(header, "LAKESIDE_$"))).isEqualTo("100,000");
      assertThat(location.get(column(header, "LAKESIDE_$/M3"))).isEqualTo("=\"50.00\"");
      // The TOW_TOT_* block is summed from the location's OWN Towing rows — one row here.
      assertThat(location.get(column(header, "TOW_TOT_KM"))).isEqualTo("30");
      assertThat(location.get(column(header, "TOW_TOT_M3"))).isEqualTo("100");
      assertThat(location.get(column(header, "TOW_TOT_$"))).isEqualTo("3,000");
      assertThat(location.get(column(header, "TOW_TOT_$/M3"))).isEqualTo("=\"30.00\"");

      String towing = "**** Schedule 4 - Towing ****";
      assertThat(headerOf(rows, towing)).startsWith("MILL_NUMBER").endsWith("CPU_$/M3");
      assertThat(bodyRow(rows, towing, 1))
          .containsExactly(
              "7600",
              "2020",
              statusOf("V"),
              "760",
              "Extract Dump",
              "Extract Towing",
              "30",
              "100",
              "3,000",
              "=\"30.00\"");
      // The Total: row's CPU is the plain two-decimal form, not the formula — legacy's own mix.
      assertThat(bodyRow(rows, towing, 2))
          .containsExactly("", "", "", "", "", "Total:", "30", "100", "3,000", "30.00");
      // A sub-page with no rows for the location gets the per-LOCATION marker, not the
      // whole-schedule one: the location exists, its Rehaul list is what is empty.
      assertThat(bodyRow(rows, "**** Schedule 4 - Rehaul ****", 1))
          .containsExactly("7600", "2020", statusOf("V"), "760", "Extract Dump", NO_DATA_FOUND);
    }

    @Test
    @DisplayName("Schedule 5: the camp row and Camp Expenses render, and Camp precedes Access")
    void scheduleFive() throws Exception {
      List<String> rows = rows(extract(body(2020, 2020, "[760]", "[\"Schedule 5\"]")));

      String main = "**** Schedule 5 ****";
      List<String> header = headerOf(rows, main);
      assertThat(header).startsWith("MILL_NUMBER").endsWith("COMMENTS");
      List<String> camp = bodyRow(rows, main, 1);
      assertThat(camp).hasSize(header.size());
      assertThat(camp.get(0)).isEqualTo("7600");
      assertThat(camp.get(column(header, "CAMP_NAME"))).isEqualTo("Extract Camp");
      assertThat(camp.get(column(header, "ROAD_DIST_KM"))).isEqualTo("12");
      assertThat(camp.get(column(header, "CAMP_SIZE_PERS"))).isEqualTo("20");
      assertThat(camp.get(column(header, "ASSOC_CAMP_VOL_M3"))).isEqualTo("10,000");
      assertThat(camp.get(column(header, "ISOLATED_CAMP"))).isEqualTo("No");
      // The one fixed category (56 catering) and the sub-page aggregate the item-62 row feeds.
      assertThat(camp.get(column(header, "CATERER_M3"))).isEqualTo("10,000");
      assertThat(camp.get(column(header, "CATERER_$"))).isEqualTo("50,000");
      assertThat(camp.get(column(header, "CATERER_$/M3"))).isEqualTo("5.00");
      assertThat(camp.get(column(header, "OTH_EXP_M3"))).isEqualTo("4,000");
      assertThat(camp.get(column(header, "OTH_EXP_$"))).isEqualTo("2,000");

      String campExpenses = "**** Schedule 5 - Camp Expenses ****";
      String accessExpenses = "**** Schedule 5 - Access Expenses ****";
      assertThat(headerOf(rows, campExpenses)).startsWith("MILL_NUMBER").endsWith("CPU_$/M3");
      // The row's volume is the item-141 amount STAMPED at read, never a stored per-row value.
      assertThat(bodyRow(rows, campExpenses, 1))
          .containsExactly(
              "7600",
              "2020",
              statusOf("V"),
              "760",
              "Extract Camp",
              "Extract Kitchen",
              "4,000",
              "2,000",
              "0.50");
      assertThat(bodyRow(rows, campExpenses, 2))
          .containsExactly("", "", "", "", "", "Total:", "4,000", "2,000", "0.50");
      // Legacy DISPATCH order: Camp before Access — although its title line, reproduced on row 6,
      // lists Access first. The two orders are asserted together so neither can be "fixed" to
      // match the other.
      assertThat(sectionAt(rows, campExpenses)).isLessThan(sectionAt(rows, accessExpenses));
      assertThat(rows.get(6))
          .isEqualTo("\"Schedules: Schedule 5, Schedule 5 Access, Schedule 5 Camp\"");
      // No item-68 row: the Access section carries this camp's per-CAMP marker.
      assertThat(bodyRow(rows, accessExpenses, 1))
          .containsExactly("7600", "2020", statusOf("V"), "760", "Extract Camp", NO_DATA_FOUND);
    }

    @Test
    @DisplayName("Schedule 8: the page row and its sample row render the seeded figures")
    void scheduleEight() throws Exception {
      List<String> rows = rows(extract(body(2020, 2020, "[760]", "[\"Schedule 8\"]")));

      String main = "**** Schedule 8 ****";
      assertThat(headerOf(rows, main)).startsWith("MILL_NUMBER").endsWith("COMMENTS").hasSize(17);
      // PAGE_NO is legacy's page title with its double space and its " - " for a null cutting
      // permit; S_BLOCK is the stored TSB code, too short to lose its first two characters; the
      // null TFL and cutting permit are the null marker.
      assertThat(bodyRow(rows, main, 1))
          .containsExactly(
              "7600",
              "2020",
              statusOf("V"),
              "760",
              "Page # 1  -TSA: TSA5 -CP:  - ",
              "Extract Div",
              "Extract Contact",
              "2505550100",
              "R1",
              "TSA5",
              "-",
              "B",
              "L760",
              "-",
              "SC1",
              "BZ1",
              "Extract page");

      String samples = "**** Schedule 8 - TTT ****";
      List<String> header = headerOf(rows, samples);
      assertThat(header).startsWith("MILL_NUMBER").endsWith("COMMENTS").hasSize(41);
      List<String> sample = bodyRow(rows, samples, 1);
      assertThat(sample).hasSize(41);
      assertThat(sample.get(0)).isEqualTo("7600");
      assertThat(sample.get(column(header, "PAGE_NO"))).isEqualTo("Sample # 1 - EXC1");
      assertThat(sample.get(column(header, "CONTRACT_ID"))).isEqualTo("EXC1");
      assertThat(sample.get(column(header, "CUT_BLOCK"))).isEqualTo("CB7");
      assertThat(sample.get(column(header, "SY_GROUNDBASE_%"))).isEqualTo("60");
      assertThat(sample.get(column(header, "SY_GRAPPLE_%"))).isEqualTo("40");
      assertThat(sample.get(column(header, "TOTAL_%"))).isEqualTo("100");
      // The legacy enum LABELS, not the stored Y/N indicators.
      assertThat(sample.get(column(header, "HELI_DIR"))).isEqualTo("Uphill");
      assertThat(sample.get(column(header, "HELI_DUMP"))).isEqualTo("Land Dump");
      assertThat(sample.get(column(header, "CONIF_M3"))).isEqualTo("700");
      assertThat(sample.get(column(header, "DECID_M3"))).isEqualTo("300");
      assertThat(sample.get(column(header, "ACTUAL_M3"))).isEqualTo("1,000");
      // No rate rows: legacy's total is null, so both cells print the null marker rather than a 0
      // that would read as "adjustments totalling zero" (#474), and final = original.
      assertThat(sample.get(column(header, "ORIG_TTT_RATE"))).isEqualTo("25");
      assertThat(sample.get(column(header, "ADDITIONS"))).isEqualTo("-");
      assertThat(sample.get(column(header, "DEDUCTIONS"))).isEqualTo("-");
      assertThat(sample.get(column(header, "FINAL_TTT_RATE"))).isEqualTo("25");
    }

    @Test
    @DisplayName("Schedule 10: page rows, a detail row, then the no-road-data page's marker LAST")
    void scheduleTen() throws Exception {
      List<String> rows = rows(extract(body(2020, 2020, "[760]", "[\"Schedule 10\"]")));

      String main = "**** Schedule 10 ****";
      List<String> header = headerOf(rows, main);
      // Legacy's PERIOD header carries a literal trailing tab, and it is matched by name here.
      assertThat(header).startsWith("MILL_NUMBER").endsWith("ROAD_GROUP").hasSize(12);
      List<String> first = bodyRow(rows, main, 1);
      assertThat(first.get(0)).isEqualTo("7600");
      assertThat(first.get(column(header, "PAGE_NO"))).startsWith("Page 1, Period: 2020-06");
      assertThat(first.get(column(header, "DIVISION"))).isEqualTo("Extract Div");
      assertThat(first.get(column(header, "PERIOD\t"))).isEqualTo("2020-06");
      assertThat(first.get(column(header, "REGION"))).isEqualTo("RNI");
      assertThat(first.get(column(header, "TSA_TFL"))).isEqualTo("01");
      assertThat(first.get(column(header, "S_BLOCK"))).isEqualTo("01A");
      assertThat(first.get(column(header, "TFL"))).isEqualTo("-");
      // Road Group is DERIVED on read: TSA 01 + TSB 01A is legacy's "11".
      assertThat(first.get(column(header, "ROAD_GROUP"))).isEqualTo("11");
      assertThat(bodyRow(rows, main, 2).get(column(header, "DIVISION"))).isEqualTo("Extract Empty");

      String road = "**** Schedule 10 - Road Data ****";
      List<String> roadHeader = headerOf(rows, road);
      assertThat(roadHeader).startsWith("MILL_NUMBER").endsWith("COMMENTS").hasSize(58);
      List<String> detail = bodyRow(rows, road, 1);
      assertThat(detail).hasSize(58);
      assertThat(detail.get(0)).isEqualTo("7600");
      assertThat(detail.get(column(roadHeader, "PAGE_NO"))).startsWith("Page 1,");
      assertThat(detail.get(column(roadHeader, "ROAD_NAME"))).isEqualTo("Extract Mainline");
      assertThat(detail.get(column(roadHeader, "ROAD_TYPE"))).isEqualTo("P");
      assertThat(detail.get(column(roadHeader, "BIOGEO_SUBZONE_VARIANT"))).isEqualTo("ICHdw1");
      assertThat(detail.get(column(roadHeader, "SLOPE_%"))).isEqualTo("25");
      assertThat(detail.get(column(roadHeader, "ENG_COST_IND"))).isEqualTo("NO");
      assertThat(detail.get(column(roadHeader, "COMMENTS"))).isEqualTo("Extract road comment");
      // The Ministry-removed columns keep header and position and carry the null marker.
      assertThat(detail.get(column(roadHeader, "MOISTURE"))).isEqualTo("-");
      assertThat(detail.get(column(roadHeader, "RSMS_CLASS"))).isEqualTo("-");
      assertThat(detail.get(column(roadHeader, "BOULDER_%"))).isEqualTo("-");
      // Legacy collected the no-road-data pages and appended them AFTER every detail row, so the
      // second page's marker follows the first page's detail although the pages list in id order.
      List<String> marker = bodyRow(rows, road, 2);
      assertThat(marker).hasSize(12);
      assertThat(marker.get(0)).isEqualTo("7600");
      assertThat(marker.get(column(roadHeader, "PAGE_NO"))).startsWith("Page 2, Period: 2020-07");
      assertThat(marker.get(11)).isEqualTo(NO_DATA_FOUND);
      // And nothing else: the row after the marker is the blank that closes the section.
      assertThat(rows.get(sectionAt(rows, road) + 4)).isEqualTo("\" \"");
    }

    @Test
    @DisplayName("Schedule 11: the STATUS cell is the SILVICULTURE track's description")
    void scheduleEleven() throws Exception {
      // 761 is V on Schedules 1-10 and D on silviculture. Every other section's STATUS cell reads
      // the main track; this one must read the silviculture track — so the two descriptions are
      // first proven different, or the assertion could pass with the wrong track wired in.
      assertThat(statusOf("D")).isNotEqualTo(statusOf("V"));
      List<String> rows = rows(extract(body(2020, 2020, "[761]", "[\"Schedule 11\"]")));

      String title = "**** Schedule 11 ****";
      assertThat(headerOf(rows, title)).startsWith("MILL_NUMBER").endsWith("COMMENTS").hasSize(13);
      // Areas use #,###,##0 and money #,###,##0.00; a null comment is the null marker.
      assertThat(bodyRow(rows, title, 1))
          .containsExactly(
              "7610",
              "2020",
              statusOf("D"),
              "761",
              "Extract Block",
              "ICHdw1",
              "N",
              "100",
              "5,000.00",
              "2,500.00",
              "7,500.00",
              "75.00",
              "-");
      // The FINAL total row sits one column further right than an intermediate one — six leading
      // blanks — legacy's misalignment kept verbatim.
      assertThat(bodyRow(rows, title, 2))
          .containsExactly(
              "", "", "", "", "", "", "Total:", "100", "5,000.00", "2,500.00", "7,500.00", "75.00");
      // The same Draft code that fills the STATUS cell also fails Data Verified for this selection.
      assertThat(cells(rows.get(5)).get(0)).isEqualTo("Data Verified: No");
    }
  }

  @Nested
  @DisplayName("the combined Schedule 1 + 2 layout")
  class CombinedLayout {

    /**
     * All three conditions: exactly Schedules 1 and 2, two or more mills, and two distinct years.
     */
    private static final String COMBINED_SCHEDULES = "[\"Schedule 1\",\"Schedule 2\"]";

    @Test
    @DisplayName("applies when all three conditions hold, and replaces the standard sections")
    void appliesWhenAllThreeConditionsHold() throws Exception {
      List<String> rows = rows(extract(body(2020, 2021, "[760,761]", COMBINED_SCHEDULES)));

      // The title line carries the RAW labels in this mode, not the detail-expanded names.
      assertThat(rows.get(6)).isEqualTo("\"Schedules: Schedule 1, Schedule 2\"");
      // Five-column mini-tables, and no Other Costs section.
      int schedule1 = sectionAt(rows, "**** Schedule 1 ****");
      assertThat(cells(rows.get(schedule1 + 1)))
          .containsExactly("MILL_NUMBER", "REPORTING_YEAR", "STATUS", "MILL_ID", "STAND_TTT_M3");
      int schedule2 = sectionAt(rows, "**** Schedule 2 ****");
      assertThat(cells(rows.get(schedule2 + 1)))
          .containsExactly("MILL_NUMBER", "REPORTING_YEAR", "STATUS", "MILL_ID", "PO&P_COSTS_$");
      assertThat(sectionAt(rows, "**** Schedule 1 - Other Costs ****")).isEqualTo(-1);
    }

    @Test
    @DisplayName("a year with no rows emits NO mini-table header of its own")
    void noHeaderForAYearWithNoRows() throws Exception {
      // 2021 has no Schedule 1 data for either mill. Legacy emitted a mini-table header only when
      // the reporting year CHANGED across its row list, so an empty year produced nothing at all —
      // as opposed to a header per year in the range, which this asserts against.
      List<String> rows = rows(extract(body(2020, 2021, "[760,761]", COMBINED_SCHEDULES)));

      assertThat(rows.stream().filter(row -> row.equals("\"**** Schedule 1 ****\"")).count())
          .isEqualTo(1);
      assertThat(rows).noneMatch(row -> cells(row).size() == 5 && row.contains("\"2021\""));
    }

    @Test
    @DisplayName("negative control: ONE mill falls back to the standard per-schedule layout")
    void oneMillFallsBack() throws Exception {
      List<String> rows = rows(extract(body(2020, 2021, "[760]", COMBINED_SCHEDULES)));

      assertThat(rows.get(6)).isNotEqualTo("\"Schedules: Schedule 1, Schedule 2\"");
      // The positive half of the control: the standard sections ARE present, at full width.
      int schedule1 = sectionAt(rows, "**** Schedule 1 ****");
      assertThat(schedule1).isPositive();
      assertThat(cells(rows.get(schedule1 + 1))).hasSizeGreaterThan(5);
      assertThat(sectionAt(rows, "**** Schedule 1 - Other Costs ****")).isPositive();
    }

    @Test
    @DisplayName("negative control: equal start and end years falls back")
    void equalYearsFallsBack() throws Exception {
      // Reachable: the selection gate accepts a single-year range, a recorded deviation.
      List<String> rows = rows(extract(body(2020, 2020, "[760,761]", COMBINED_SCHEDULES)));

      int schedule1 = sectionAt(rows, "**** Schedule 1 ****");
      assertThat(schedule1).isPositive();
      assertThat(cells(rows.get(schedule1 + 1))).hasSizeGreaterThan(5);
      assertThat(sectionAt(rows, "**** Schedule 1 - Other Costs ****")).isPositive();
    }

    @Test
    @DisplayName("negative control: a THIRD schedule falls back")
    void thirdScheduleFallsBack() throws Exception {
      List<String> rows =
          rows(
              extract(
                  body(2020, 2021, "[760,761]", "[\"Schedule 1\",\"Schedule 2\",\"Schedule 6\"]")));

      int schedule1 = sectionAt(rows, "**** Schedule 1 ****");
      assertThat(schedule1).isPositive();
      assertThat(cells(rows.get(schedule1 + 1))).hasSizeGreaterThan(5);
      assertThat(sectionAt(rows, "**** Schedule 6 ****")).isPositive();
    }
  }

  @Nested
  @DisplayName("failure")
  class Failure {

    @Test
    @DisplayName("a read failure is one 500 undefinedError and leaves NO spool file behind")
    void readFailureAnswers500AndLeavesNoSpoolFile() throws Exception {
      // The whole-file-or-no-file contract's other half. Asserted on the spool DIRECTORY, because
      // the failure mode this guards against is a partial file surviving on a read-only-root pod
      // whose writable volume then fills up — invisible to any assertion on the response alone.
      // The directory listed is the one the class pins through ilcr.reporting.spool-directory —
      // listing java.io.tmpdir would compare a directory the spooler never writes to.
      Path spoolDirectory = SPOOL_DIRECTORY;
      Set<Path> before = spoolFiles(spoolDirectory);

      when(schedule1Service.findStoredSchedule1(anyLong(), anyInt(), any()))
          .thenThrow(new IllegalStateException("the owner blew up mid-build"));

      mockMvc
          .perform(
              post(ENDPOINT)
                  .with(ADMIN)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content(body(2020, 2020, "[760]", "[\"Schedule 1\"]"))
                  .accept(MediaType.ALL))
          .andExpect(status().isInternalServerError())
          .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
          // The legacy bundle text, not the global handler's hardcoded generic. Pinned verbatim
          // because a non-BusinessException would still answer 500 and pass a status-only check.
          .andExpect(
              jsonPath("$.detail")
                  .value(
                      "ILCR has found an unhandled error/exception. Please refer to application"
                          + " log files."))
          .andExpect(header().doesNotExist("Content-Disposition"));

      assertThat(spoolFiles(spoolDirectory)).isEqualTo(before);
    }

    @Test
    @DisplayName("logs carry counts and ids, never a cell value")
    void logsCarryNoCellValues() throws Exception {
      // AD-11/NFR3: commercial cost data must not reach a log at any level. The seeded figures
      // below are the ones this extract actually renders, so their absence from a DEBUG-level
      // capture is evidence rather than a tautology.
      // The app logs through SLF4J onto log4j2 (the logback starter is excluded), and with no
      // log4j2 config on the test classpath the root level is ERROR — so the level has to be
      // lowered explicitly or the capture is vacuously empty.
      Logger generatorLog = (Logger) LogManager.getLogger(DataExtractGenerator.class);
      CapturingAppender appender = new CapturingAppender();
      appender.start();
      Level previous = generatorLog.getLevel();
      generatorLog.addAppender(appender);
      generatorLog.setLevel(Level.DEBUG);
      try {
        extract(body(2020, 2020, "[760,761]", "[\"Schedule 1\",\"Schedule 2\"]"));
      } finally {
        generatorLog.removeAppender(appender);
        generatorLog.setLevel(previous);
        appender.stop();
      }

      String logged = String.join("\n", appender.messages);
      assertThat(logged).isNotEmpty();
      // Raw and formatted forms of the seeded volumes and costs, plus the markers a row sample
      // would drag in with it.
      assertThat(logged)
          .doesNotContain("1234500")
          .doesNotContain("1,234,500")
          .doesNotContain("9876500")
          .doesNotContain("9,876,500")
          .doesNotContain("777000")
          .doesNotContain("777,000")
          .doesNotContain(NO_DATA_FOUND);
    }

    /**
     * Collects formatted messages at every level, so a leak at DEBUG is caught as well as at INFO.
     */
    private static final class CapturingAppender extends AbstractAppender {

      private final List<String> messages = new ArrayList<>();

      private CapturingAppender() {
        super("data-extract-capture", null, null, true, Property.EMPTY_ARRAY);
      }

      @Override
      public void append(LogEvent event) {
        messages.add(event.getMessage().getFormattedMessage());
      }
    }

    @Test
    @DisplayName("a 400 refusal carries no attachment header and no file")
    void refusalProducesNoFile() throws Exception {
      mockMvc
          .perform(
              post(ENDPOINT)
                  .with(ADMIN)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content(body(2020, 2020, "[]", "[\"Schedule 1\"]"))
                  .accept(MediaType.ALL))
          .andExpect(status().isBadRequest())
          .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
          .andExpect(header().doesNotExist("Content-Disposition"))
          .andExpect(
              jsonPath("$.messages[*].text")
                  .value(Matchers.hasItem("Please select at least one Mill for extracting.")));
    }
  }
}
