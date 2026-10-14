package ca.bc.gov.nrs.ilcr.millmaintenance;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test — the mill lifecycle (UC-MILL-001), security ON. Runs the real cognito:groups →
 * role → action path, so the ADMIN-only gate, the verbatim legacy messages and the audit-column
 * discipline are exercised exactly as a caller meets them.
 *
 * <p>Each test removes the rows it created and restores any seeded row it moved, so the JVM-wide
 * container stays at its seeded baseline for other IT classes. That matters more here than usual:
 * importing a mill creates a current-year report-status row, and the count of those rows for 2021
 * is asserted directly by {@code MillReportStatusIT}.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Mill administration — search, import, status and contacts (admin-gated)")
class MillMaintenanceIT extends AbstractOracleIT {

  /** Untracked ministry mill: a MILL row with no cross-reference, the only importable shape. */
  private static final long UNTRACKED_MILL = 750L;

  /** ACT with no assignments — the deactivation success path. Mixed-case name on purpose. */
  private static final long ACTIVE_MILL = 751L;

  /** ACT with one active assignment — the deactivation block (BR-01/S12). */
  private static final long ACTIVE_MILL_WITH_USER = 752L;

  /** CLS with no current-year report records — activation must create them (BR-07). */
  private static final long CLOSED_MILL = 753L;

  /** CLS used for the branch where records already exist; the test creates them itself. */
  private static final long CLOSED_MILL_WITH_RECORDS = 754L;

  /** ACT linked to a client location holding two contacts — the head-office/contact save. */
  private static final long MILL_WITH_CONTACTS = 755L;

  /** The two contacts on mill 755's own client location (BR-09 selectable). */
  private static final long OWN_HEAD_OFFICE_CONTACT = 7551L;

  private static final long OWN_DIVISION_CONTACT = 7552L;

  /** A real contact on a DIFFERENT client location — the BR-09 negative case. */
  private static final long FOREIGN_CONTACT = 7561L;

  /** The reporting year the shared snapshot's periods make current (2021 and 2020 are open). */
  private static final int CURRENT_YEAR = 2021;

  /**
   * The acting administrator's {@code custom:idp_username}, expected in the audit columns. A
   * synthetic value — a real person's identifier must never be hardcoded.
   */
  private static final String ADMIN_USERNAME = "TESTADMN";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  @Autowired private JdbcTemplate jdbcTemplate;

  @AfterEach
  void cleanUp() {
    // The import test's rows, in FK-safe order. Report records first: nothing depends on them, but
    // leaving a 2021 status row behind would break another class's assertion on the count of them.
    jdbcTemplate.update(
        "DELETE FROM THE.ILCR_REPORT_CATEGORY WHERE ILCR_MILL_ID IN (?, ?, ?)",
        UNTRACKED_MILL,
        CLOSED_MILL,
        CLOSED_MILL_WITH_RECORDS);
    jdbcTemplate.update(
        "DELETE FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID IN (?, ?, ?)",
        UNTRACKED_MILL,
        CLOSED_MILL,
        CLOSED_MILL_WITH_RECORDS);
    jdbcTemplate.update(
        "DELETE FROM THE.ILCR_MILL_STATUS_XREF WHERE ILCR_MILL_STATUS_XREF_ID = ?", UNTRACKED_MILL);

    // Restore the seeded status and contact state of the rows the status/contact tests move.
    resetMill(ACTIVE_MILL, "ACT");
    // The deactivate-success test re-stamps these to prove the write happened; restored here so the
    // detail-read test's assertion of the seeded placeholder values does not depend on test order.
    jdbcTemplate.update(
        // Deliberately NOT midnight: the column is TIMESTAMP(6) and the wire contract is a date, so
        // a DATE literal here would have left the narrowing untested -- an afternoon time is what
        // catches a conversion that rolls the date forward or refuses the column outright.
        "UPDATE THE.ILCR_MILL_STATUS_XREF SET UPDATE_USERID = 'ITUSER', "
            + "UPDATE_TIMESTAMP = TIMESTAMP '2026-09-01 14:37:12.123456' "
            + "WHERE ILCR_MILL_STATUS_XREF_ID = ?",
        ACTIVE_MILL);
    resetMill(ACTIVE_MILL_WITH_USER, "ACT");
    resetMill(CLOSED_MILL, "CLS");
    resetMill(CLOSED_MILL_WITH_RECORDS, "CLS");
    jdbcTemplate.update(
        "UPDATE THE.ILCR_MILL_STATUS_XREF SET ILCR_MILL_STATUS_CODE = 'ACT', "
            + "HEAD_OFFICE_CONTACT_IND = NULL, HEAD_OFFICE_CONTACT_ID = NULL, "
            + "DIVISION_CONTACT_ID = NULL, REVISION_COUNT = 0 "
            + "WHERE ILCR_MILL_STATUS_XREF_ID = ?",
        MILL_WITH_CONTACTS);
  }

  // ---------------------------------------------------------------- search (AC1)

  @Test
  @DisplayName("Search by status returns tracked mills with their status description")
  void searchByStatusReturnsTrackedMills() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills").param("status", "CLS").with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.results[?(@.millId == " + CLOSED_MILL + ")]").exists())
        .andExpect(
            jsonPath("$.results[?(@.millId == " + CLOSED_MILL + ")].statusDescription")
                .value("Close"))
        // No message when there are results: Jackson omits the nulls entirely.
        .andExpect(jsonPath("$.messageKey").doesNotExist())
        .andExpect(jsonPath("$.message").doesNotExist());
  }

  @Test
  @DisplayName("Search by exact mill number returns only that mill")
  void searchByMillNumberIsExact() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills").param("millNumber", "7510").with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.results.length()").value(1))
        .andExpect(jsonPath("$.results[0].millId").value(ACTIVE_MILL))
        .andExpect(jsonPath("$.results[0].millStatusCode").value("ACT"))
        .andExpect(jsonPath("$.results[0].statusDescription").value("Active"));
  }

  @Test
  @DisplayName("Name search is case-insensitive on both sides")
  void nameSearchIsCaseInsensitive() throws Exception {
    // Mill 751 is stored 'Cariboo Maintain Mill'. Legacy upper-cased only the bind parameter, so
    // this lower-case term became LIKE '%CARIBOO%' and matched nothing — the search was unusable
    // for any mill whose stored name was not already upper-case.
    mockMvc
        .perform(get("/api/v1/admin/mills").param("millName", "cariboo").with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.results[0].millId").value(ACTIVE_MILL));
  }

  @Test
  @DisplayName("A typed LIKE wildcard matches literally, not as a wildcard")
  void nameSearchEscapesLikeMetacharacters() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills").param("millName", "%").with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.results.length()").value(0))
        .andExpect(jsonPath("$.messageKey").value("mill.not.found"));
  }

  @Test
  @DisplayName("A zero-match search is 200 with the verbatim legacy not-found message (S11)")
  void zeroMatchSearchCarriesTheLegacyMessage() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills").param("millNumber", "99999999").with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.results.length()").value(0))
        .andExpect(jsonPath("$.messageKey").value("mill.not.found"))
        .andExpect(
            jsonPath("$.message")
                .value(
                    "No mill matching this criteria has been found. Please ensure the "
                        + "ilcr_mill_status_xref ID matches with mill ID or try importing the mill."));
  }

  @Test
  @DisplayName("An unknown status criterion is refused, not answered as a zero-match")
  void unknownStatusCriterionIsRefused() throws Exception {
    // Legacy's fixed dropdown made this unreachable; a zero-match 200 here would tell the caller to
    // "try importing the mill" for what is actually a malformed request.
    mockMvc
        .perform(get("/api/v1/admin/mills").param("status", "CLOSED").with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail").value(containsString("is not a mill status")));
  }

  @Test
  @DisplayName("A non-numeric mill number is refused with the ported legacy converter text (S15)")
  void nonNumericMillNumberIsRefused() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills").param("millNumber", "abc").with(admin()))
        .andExpect(status().isBadRequest())
        // The resolved text, not just the status: a key carrying {n} placeholders and doubled ''
        // escapes that reached the client unresolved would still be a 400 and still pass a
        // status-only assertion.
        .andExpect(
            jsonPath("$.detail")
                .value(
                    "Number: 'abc' must be replaced with a number consisting of one or more "
                        + "digits - decimal values are not accepted."));
  }

  @Test
  @DisplayName("An untracked ministry mill never appears in the ILCR search")
  void searchExcludesUntrackedMills() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills").param("millNumber", "7500").with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.results.length()").value(0));
  }

  @Test
  @DisplayName("The admin detail read returns the full mill record")
  void detailReadReturnsTheMill() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills/{id}", ACTIVE_MILL).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.millId").value(ACTIVE_MILL))
        .andExpect(jsonPath("$.millNumber").value("7510"))
        .andExpect(jsonPath("$.millName").value("Cariboo Maintain Mill"))
        .andExpect(jsonPath("$.millStatusCode").value("ACT"))
        .andExpect(jsonPath("$.statusDescription").value("Active"))
        .andExpect(jsonPath("$.revisionCount").value(0))
        // The source for legacy's "Last Edited by : … on date: …" line (mills.xhtml:41-49,
        // deviation (A) closed): the fixture seeds these to fixed values so this proves the
        // projection carries real data, not merely that the columns are non-null.
        .andExpect(jsonPath("$.updateUserid").value("ITUSER"))
        // Day precision, and the right day: the fixture's timestamp carries 14:37:12.123456, which
        // must be dropped rather than rounded or zone-shifted into the 2nd.
        .andExpect(jsonPath("$.updateTimestamp").value("2026-09-01"));
  }

  // ---------------------------------------------------------------- import (AC2)

  @Test
  @DisplayName("The importable list offers only mills with no cross-reference (BR-04)")
  void importableListExcludesTrackedMills() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills/importable").with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[?(@.millId == " + UNTRACKED_MILL + ")]").exists())
        .andExpect(jsonPath("$[?(@.millId == " + ACTIVE_MILL + ")]").doesNotExist())
        .andExpect(jsonPath("$[?(@.millId == " + CLOSED_MILL + ")]").doesNotExist());
  }

  @Test
  @DisplayName("The importable list filters by number and name and keeps the mill-number order")
  void importableListFiltersAndOrders() throws Exception {
    // Fixture 756 exists precisely so the ordering is provable: with both untracked mills matching
    // a name fragment, 7500 must precede 7560.
    mockMvc
        .perform(get("/api/v1/admin/mills/importable").param("millName", "untracked").with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(2))
        .andExpect(jsonPath("$[0].millId").value(UNTRACKED_MILL))
        .andExpect(jsonPath("$[1].millId").value(756));

    mockMvc
        .perform(get("/api/v1/admin/mills/importable").param("millNumber", "7560").with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(1))
        .andExpect(jsonPath("$[0].millId").value(756));

    // The number parse is shared with the ILCR search, refusal included.
    mockMvc
        .perform(get("/api/v1/admin/mills/importable").param("millNumber", "abc").with(admin()))
        .andExpect(status().isBadRequest());
  }

  @Test
  @DisplayName(
      "Import creates the cross-reference closed with head-office Y and the report records")
  void importCreatesTheCrossReferenceAndReportRecords() throws Exception {
    mockMvc
        .perform(post("/api/v1/admin/mills/{id}/import", UNTRACKED_MILL).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.mill.millId").value(UNTRACKED_MILL))
        .andExpect(jsonPath("$.mill.millStatusCode").value("CLS"))
        .andExpect(jsonPath("$.mill.headOfficeContactInd").value("Y"))
        // Both contact slots start empty; Jackson omits the nulls.
        .andExpect(jsonPath("$.mill.headOfficeContactId").doesNotExist())
        .andExpect(jsonPath("$.mill.divisionContactId").doesNotExist())
        .andExpect(jsonPath("$.mill.revisionCount").value(0))
        // No confirmation sentence: legacy's import confirmed only by displaying the mill's
        // details, so the envelope carries no message (review decision 2026-09-09).
        .andExpect(jsonPath("$.messageKey").doesNotExist())
        .andExpect(jsonPath("$.message").doesNotExist());

    Map<String, Object> xref = xrefRow(UNTRACKED_MILL);
    assertEquals("CLS", xref.get("ILCR_MILL_STATUS_CODE"));
    assertEquals("Y", xref.get("HEAD_OFFICE_CONTACT_IND"));
    assertEquals("Imported from ISP Mill table", xref.get("COMMENTS"));
    assertNull(xref.get("HEAD_OFFICE_CONTACT_ID"));
    assertNull(xref.get("DIVISION_CONTACT_ID"));

    // The report records BR-03 requires: one status row with both tracks Draft, and one row per
    // schedule category.
    assertEquals(1, statusRowCount(UNTRACKED_MILL, CURRENT_YEAR));
    assertEquals(11, categoryRowCount(UNTRACKED_MILL, CURRENT_YEAR));
    Map<String, Object> statusRow = statusRow(UNTRACKED_MILL, CURRENT_YEAR);
    assertEquals("D", statusRow.get("ILCR_MILL_REPORT_STATUS_CODE"));
    assertEquals("D", statusRow.get("MILL_SILVICULTUR_STATUS_CODE"));
    assertEquals("N", statusRow.get("REPORT_COMPLETED_IND"));
  }

  @Test
  @DisplayName("Import stamps the audit columns from the acting administrator")
  void importStampsTheAuditColumns() throws Exception {
    mockMvc
        .perform(post("/api/v1/admin/mills/{id}/import", UNTRACKED_MILL).with(admin()))
        .andExpect(status().isOk());

    Map<String, Object> xref = xrefRow(UNTRACKED_MILL);
    // The raw custom:idp_username claim, not the provider-prefixed form, which would not fit the
    // 30-character column.
    assertEquals(ADMIN_USERNAME, xref.get("ENTRY_USERID"));
    assertEquals(ADMIN_USERNAME, xref.get("UPDATE_USERID"));
    assertNotNull(xref.get("ENTRY_TIMESTAMP"));
    assertNotNull(xref.get("UPDATE_TIMESTAMP"));
    assertEquals(0, ((Number) xref.get("REVISION_COUNT")).intValue());
  }

  @Test
  @DisplayName("Importing an already-tracked mill is refused and changes nothing")
  void importingATrackedMillIsRefused() throws Exception {
    mockMvc
        .perform(post("/api/v1/admin/mills/{id}/import", ACTIVE_MILL).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail").value(containsString("already tracked")));

    assertEquals("ACT", statusCode(ACTIVE_MILL));
  }

  @Test
  @DisplayName("Importing an unknown mill is not found")
  void importingAnUnknownMillIsNotFound() throws Exception {
    mockMvc
        .perform(post("/api/v1/admin/mills/{id}/import", 88888L).with(admin()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail").value("The selected mill could not be found."));
  }

  @Test
  @DisplayName("A failed import rolls back completely with the legacy failure message (S14)")
  void aFailedImportRollsBackWithTheLegacyMessage() throws Exception {
    // A stray current-year status row with no cross-reference — the partial state a past failure
    // can leave. The import's own report-record insert then collides on the composite PK, and S14
    // requires the whole transaction to vanish: no cross-reference, the legacy failure text.
    jdbcTemplate.update(
        "INSERT INTO THE.ILCR_MILL_REPORT_STATUS (REPORT_YEAR, ILCR_MILL_ID, "
            + "ILCR_MILL_REPORT_STATUS_CODE, MILL_SILVICULTUR_STATUS_CODE, REPORT_COMPLETED_IND, "
            + "REVISION_COUNT, ENTRY_USERID, ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP) "
            + "VALUES (?, ?, 'D', 'D', 'N', 0, 'SEED', SYSDATE, 'SEED', SYSDATE)",
        CURRENT_YEAR,
        UNTRACKED_MILL);

    mockMvc
        .perform(post("/api/v1/admin/mills/{id}/import", UNTRACKED_MILL).with(admin()))
        .andExpect(status().isInternalServerError())
        .andExpect(
            jsonPath("$.detail").value("ILCR cannot import the Mill. Please refer to logs."));

    // Rolled back completely: the cross-reference does not survive, and no category rows appeared.
    assertTrue(xrefRow(UNTRACKED_MILL).isEmpty());
    assertEquals(0, categoryRowCount(UNTRACKED_MILL, CURRENT_YEAR));
  }

  // ---------------------------------------------------------------- deactivate (AC3)

  @Test
  @DisplayName("Deactivating a mill with no active users succeeds (S03/SUC-002)")
  void deactivateSucceedsWithoutActiveUsers() throws Exception {
    mockMvc
        .perform(changeStatus("/api/v1/admin/mills/{id}/deactivate", ACTIVE_MILL, 0))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.mill.millStatusCode").value("CLS"))
        .andExpect(jsonPath("$.messageKey").value("mill.expired"))
        .andExpect(
            jsonPath("$.message").value("Mill 7510 - Cariboo Maintain Mill has been deactivated."));

    assertEquals("CLS", statusCode(ACTIVE_MILL));
    assertEquals(ADMIN_USERNAME, xrefRow(ACTIVE_MILL).get("UPDATE_USERID"));
    // The seeded row carries the fixed placeholder 2026-09-01 (R__75), so a value that is no longer
    // that placeholder proves this write re-stamped it — a plain non-null check would pass on the
    // untouched seed too.
    assertNotEquals(
        java.sql.Timestamp.valueOf("2026-09-01 00:00:00"),
        xrefRow(ACTIVE_MILL).get("UPDATE_TIMESTAMP"));
    assertNotNull(xrefRow(ACTIVE_MILL).get("UPDATE_TIMESTAMP"));
    assertEquals(1, ((Number) xrefRow(ACTIVE_MILL).get("REVISION_COUNT")).intValue());
  }

  @Test
  @DisplayName("Deactivation is blocked while an assignment is active, status unchanged (S12)")
  void deactivateIsBlockedByAnActiveAssignment() throws Exception {
    mockMvc
        .perform(changeStatus("/api/v1/admin/mills/{id}/deactivate", ACTIVE_MILL_WITH_USER, 0))
        .andExpect(status().isConflict())
        .andExpect(
            jsonPath("$.detail")
                .value("The selected mill has active users, you must deactivate them first."));

    // The refusal must leave the row exactly as it was — including the revision, so a retry after
    // ending the assignment still works with the revision the screen already holds.
    assertEquals("ACT", statusCode(ACTIVE_MILL_WITH_USER));
    assertEquals(0, ((Number) xrefRow(ACTIVE_MILL_WITH_USER).get("REVISION_COUNT")).intValue());
  }

  @Test
  @DisplayName("Ending the assignment first then deactivating succeeds")
  void deactivateSucceedsOnceTheAssignmentIsEnded() throws Exception {
    jdbcTemplate.update(
        "UPDATE THE.ILCR_MILL_USER_XREF SET ACTIVE_DATE = NULL, INACTIVE_DATE = SYSDATE "
            + "WHERE ILCR_MILL_ID = ?",
        ACTIVE_MILL_WITH_USER);
    try {
      mockMvc
          .perform(changeStatus("/api/v1/admin/mills/{id}/deactivate", ACTIVE_MILL_WITH_USER, 0))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.mill.millStatusCode").value("CLS"));
    } finally {
      jdbcTemplate.update(
          "UPDATE THE.ILCR_MILL_USER_XREF SET ACTIVE_DATE = SYSDATE, INACTIVE_DATE = NULL "
              + "WHERE ILCR_MILL_ID = ?",
          ACTIVE_MILL_WITH_USER);
    }
  }

  // ---------------------------------------------------------------- activate (AC4)

  @Test
  @DisplayName("Activating a closed mill restores ACT and creates the current-year records (BR-07)")
  void activateCreatesMissingReportRecords() throws Exception {
    assertEquals(0, statusRowCount(CLOSED_MILL, CURRENT_YEAR));

    mockMvc
        .perform(changeStatus("/api/v1/admin/mills/{id}/activate", CLOSED_MILL, 0))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.mill.millStatusCode").value("ACT"))
        .andExpect(jsonPath("$.messageKey").value("mill.activated"))
        .andExpect(
            jsonPath("$.message")
                .value("Mill 7530 - CLOSED MILL AWAITING RECORDS has been activated."));

    assertEquals("ACT", statusCode(CLOSED_MILL));
    assertEquals(1, statusRowCount(CLOSED_MILL, CURRENT_YEAR));
    assertEquals(11, categoryRowCount(CLOSED_MILL, CURRENT_YEAR));
  }

  @Test
  @DisplayName("Activating a mill that already has records creates no duplicates")
  void activateLeavesExistingRecordsAlone() throws Exception {
    // Created here rather than seeded: a 2021 status row in the shared fixtures would change the
    // count another IT class asserts.
    //
    // The COMPLETE set is seeded, status row plus all eleven categories, because that is the only
    // shape delivery actually holds — every one of its 118 enrolled (mill, year) pairs carries
    // exactly eleven category rows (verified 2026-09-10). Seeding the status row alone would seed a
    // half-enrolled mill, which is now a conflict and is covered by its own test below.
    seedCompleteReportRecords(CLOSED_MILL_WITH_RECORDS);

    mockMvc
        .perform(changeStatus("/api/v1/admin/mills/{id}/activate", CLOSED_MILL_WITH_RECORDS, 0))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.mill.millStatusCode").value("ACT"));

    // Nothing was duplicated and the existing status row keeps the state it had: the guarantee is
    // "records exist", not "records are reset".
    assertEquals(1, statusRowCount(CLOSED_MILL_WITH_RECORDS, CURRENT_YEAR));
    assertEquals(11, categoryRowCount(CLOSED_MILL_WITH_RECORDS, CURRENT_YEAR));
    assertEquals(
        "S", statusRow(CLOSED_MILL_WITH_RECORDS, CURRENT_YEAR).get("ILCR_MILL_REPORT_STATUS_CODE"));
  }

  @Test
  @DisplayName("Activation over partial report records is a named conflict and rolls back (D7)")
  void activationOverPartialRecordsIsANamedConflict() throws Exception {
    // One partial state: category rows present but the status row absent. Legacy 500'd this as its
    // generic unhandled error; D7 rules a business conflict that leaves the mill exactly as found.
    jdbcTemplate.update(
        "INSERT INTO THE.ILCR_REPORT_CATEGORY (REPORT_YEAR, ILCR_MILL_ID, ILCR_CATEGORY_ID, "
            + "CATEGORY_STATE_CODE, REPORTABLE_DETAIL_IND, REVISION_COUNT, ENTRY_USERID, "
            + "ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP) "
            + "VALUES (?, ?, '3', 'D', 'Y', 0, 'SEED', SYSDATE, 'SEED', SYSDATE)",
        CURRENT_YEAR,
        CLOSED_MILL);

    mockMvc
        .perform(changeStatus("/api/v1/admin/mills/{id}/activate", CLOSED_MILL, 0))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail").value(containsString("incomplete")));

    // The status change rolled back with the enrolment: the mill is left closed at revision 0.
    assertEquals("CLS", statusCode(CLOSED_MILL));
    assertEquals(0, ((Number) xrefRow(CLOSED_MILL).get("REVISION_COUNT")).intValue());
    assertEquals(0, statusRowCount(CLOSED_MILL, CURRENT_YEAR));
  }

  @Test
  @DisplayName("A status row without its category rows is refused, not reported as activated")
  void activationOverAStatusRowMissingItsCategoriesIsRefused() throws Exception {
    // The mirror partial state, and the one that used to pass. The enrolment check asked only
    // whether the report-status row existed, so this mill activated with a 200 while nine of its
    // eleven category rows were missing — the endpoint reported a mill enrolled that still lacked
    // the records BR-07 promises, and said nothing. Both partial states now answer the same
    // conflict.
    jdbcTemplate.update(
        "INSERT INTO THE.ILCR_MILL_REPORT_STATUS (REPORT_YEAR, ILCR_MILL_ID, "
            + "ILCR_MILL_REPORT_STATUS_CODE, MILL_SILVICULTUR_STATUS_CODE, REPORT_COMPLETED_IND, "
            + "REVISION_COUNT, ENTRY_USERID, ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP) "
            + "VALUES (?, ?, 'D', 'D', 'N', 0, 'SEED', SYSDATE, 'SEED', SYSDATE)",
        CURRENT_YEAR,
        CLOSED_MILL_WITH_RECORDS);
    // Two of eleven: enough that the status row exists, few enough that the set is incomplete.
    // A count-based check is what tells this from the complete set — an existence check cannot.
    for (String categoryId : List.of("1", "2")) {
      jdbcTemplate.update(
          "INSERT INTO THE.ILCR_REPORT_CATEGORY (REPORT_YEAR, ILCR_MILL_ID, ILCR_CATEGORY_ID, "
              + "CATEGORY_STATE_CODE, REPORTABLE_DETAIL_IND, REVISION_COUNT, ENTRY_USERID, "
              + "ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP) "
              + "VALUES (?, ?, ?, 'D', 'Y', 0, 'SEED', SYSDATE, 'SEED', SYSDATE)",
          CURRENT_YEAR,
          CLOSED_MILL_WITH_RECORDS,
          categoryId);
    }

    mockMvc
        .perform(changeStatus("/api/v1/admin/mills/{id}/activate", CLOSED_MILL_WITH_RECORDS, 0))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail").value(containsString("incomplete")));

    // Left exactly as found: still closed, still at revision 0, and the incomplete set is NOT
    // repaired — completing it would guess at what the missing rows should hold.
    assertEquals("CLS", statusCode(CLOSED_MILL_WITH_RECORDS));
    assertEquals(0, ((Number) xrefRow(CLOSED_MILL_WITH_RECORDS).get("REVISION_COUNT")).intValue());
    assertEquals(2, categoryRowCount(CLOSED_MILL_WITH_RECORDS, CURRENT_YEAR));
  }

  @Test
  @DisplayName(
      "A status change omitting the revision is rejected rather than treated as revision 0")
  void statusChangeRequiresTheRevision() throws Exception {
    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/activate", CLOSED_MILL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(admin()))
        .andExpect(status().isBadRequest());
    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/deactivate", ACTIVE_MILL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(admin()))
        .andExpect(status().isBadRequest());

    // Neither refusal wrote anything.
    assertEquals("CLS", statusCode(CLOSED_MILL));
    assertEquals("ACT", statusCode(ACTIVE_MILL));
  }

  // ---------------------------------------------------------------- contacts (AC5)

  @Test
  @DisplayName("Contact options are limited to the mill's own client location (BR-09)")
  void contactOptionsAreLimitedToTheMillsClientLocation() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills/{id}/contact-options", MILL_WITH_CONTACTS).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(2))
        // Ordered by name, so ABBOTT precedes ZAMORA even though its id is higher.
        .andExpect(jsonPath("$[0].clientContactId").value(OWN_DIVISION_CONTACT))
        .andExpect(jsonPath("$[0].contactName").value("ABBOTT DIVISION"))
        .andExpect(jsonPath("$[1].clientContactId").value(OWN_HEAD_OFFICE_CONTACT))
        .andExpect(jsonPath("$[?(@.clientContactId == " + FOREIGN_CONTACT + ")]").doesNotExist());
  }

  @Test
  @DisplayName("Saving the head-office indicator and both contacts persists them (S01/SUC-001)")
  void saveContactsPersistsTheSelections() throws Exception {
    mockMvc
        .perform(
            saveContacts(MILL_WITH_CONTACTS, "Y", OWN_HEAD_OFFICE_CONTACT, OWN_DIVISION_CONTACT, 0))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.mill.headOfficeContactInd").value("Y"))
        .andExpect(jsonPath("$.mill.headOfficeContactId").value(OWN_HEAD_OFFICE_CONTACT))
        .andExpect(jsonPath("$.mill.divisionContactId").value(OWN_DIVISION_CONTACT))
        .andExpect(jsonPath("$.messageKey").value("mill.updated"))
        .andExpect(
            jsonPath("$.message").value("Mill 7550 - MAINTAIN MILL WITH CONTACTS has been saved."));

    Map<String, Object> xref = xrefRow(MILL_WITH_CONTACTS);
    assertEquals("Y", xref.get("HEAD_OFFICE_CONTACT_IND"));
    assertEquals(
        OWN_HEAD_OFFICE_CONTACT, ((Number) xref.get("HEAD_OFFICE_CONTACT_ID")).longValue());
    assertEquals(OWN_DIVISION_CONTACT, ((Number) xref.get("DIVISION_CONTACT_ID")).longValue());
    // The status code is not the save panel's to change.
    assertEquals("ACT", xref.get("ILCR_MILL_STATUS_CODE"));
    assertEquals(ADMIN_USERNAME, xref.get("UPDATE_USERID"));
    // Non-null proves the update path stamped the timestamp; the loosened snapshot would accept an
    // omission that delivery refuses (ORA-01400).
    assertNotNull(xref.get("UPDATE_TIMESTAMP"));
  }

  @Test
  @DisplayName("A null contact selection clears the stored contact")
  void saveContactsClearsWithNull() throws Exception {
    mockMvc
        .perform(
            saveContacts(MILL_WITH_CONTACTS, "Y", OWN_HEAD_OFFICE_CONTACT, OWN_DIVISION_CONTACT, 0))
        .andExpect(status().isOk());

    mockMvc
        .perform(saveContacts(MILL_WITH_CONTACTS, "N", null, null, 1))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.mill.headOfficeContactInd").value("N"))
        .andExpect(jsonPath("$.mill.headOfficeContactId").doesNotExist());

    Map<String, Object> xref = xrefRow(MILL_WITH_CONTACTS);
    assertNull(xref.get("HEAD_OFFICE_CONTACT_ID"));
    assertNull(xref.get("DIVISION_CONTACT_ID"));
  }

  @Test
  @DisplayName("A contact from another client location is refused (BR-09)")
  void saveContactsRefusesAForeignContact() throws Exception {
    mockMvc
        .perform(saveContacts(MILL_WITH_CONTACTS, "Y", FOREIGN_CONTACT, null, 0))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail").value(containsString("does not belong to this mill")));

    // Refused before any write: legacy stored it silently, so proving nothing changed is the point.
    assertNull(xrefRow(MILL_WITH_CONTACTS).get("HEAD_OFFICE_CONTACT_ID"));
    assertEquals(0, ((Number) xrefRow(MILL_WITH_CONTACTS).get("REVISION_COUNT")).intValue());
  }

  @Test
  @DisplayName("An indicator outside Y/N is rejected at the request boundary")
  void saveContactsRejectsAnInvalidIndicator() throws Exception {
    mockMvc
        .perform(saveContacts(MILL_WITH_CONTACTS, "MAYBE", null, null, 0))
        .andExpect(status().isBadRequest());
  }

  @Test
  @DisplayName("A body omitting the revision is rejected rather than treated as revision 0")
  void saveContactsRequiresTheRevision() throws Exception {
    mockMvc
        .perform(
            put("/api/v1/admin/mills/{id}/contacts", MILL_WITH_CONTACTS)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"headOfficeContactInd\":\"Y\"}")
                .with(admin()))
        .andExpect(status().isBadRequest());
  }

  // ---------------------------------------------------------------- concurrency + authorization

  @Test
  @DisplayName("A stale revision is refused without overwriting")
  void aStaleRevisionIsRefused() throws Exception {
    mockMvc
        .perform(saveContacts(MILL_WITH_CONTACTS, "Y", null, null, 0))
        .andExpect(status().isOk());

    // The revision the caller still holds is now one behind.
    mockMvc
        .perform(saveContacts(MILL_WITH_CONTACTS, "N", null, null, 0))
        .andExpect(status().isConflict());

    assertEquals("Y", xrefRow(MILL_WITH_CONTACTS).get("HEAD_OFFICE_CONTACT_IND"));
  }

  @Test
  @DisplayName("A stale revision is refused on a status change too")
  void aStaleRevisionIsRefusedOnStatusChange() throws Exception {
    mockMvc
        .perform(changeStatus("/api/v1/admin/mills/{id}/deactivate", ACTIVE_MILL, 7))
        .andExpect(status().isConflict());

    assertEquals("ACT", statusCode(ACTIVE_MILL));
  }

  @Test
  @DisplayName("A submitter is denied every operation")
  void submitterIsDeniedEveryOperation() throws Exception {
    mockMvc.perform(get("/api/v1/admin/mills").with(submitter())).andExpect(status().isForbidden());
    mockMvc
        .perform(get("/api/v1/admin/mills/importable").with(submitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(get("/api/v1/admin/mills/{id}", ACTIVE_MILL).with(submitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(get("/api/v1/admin/mills/{id}/contact-options", ACTIVE_MILL).with(submitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(post("/api/v1/admin/mills/{id}/import", UNTRACKED_MILL).with(submitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/activate", CLOSED_MILL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"revisionCount\":0}")
                .with(submitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/deactivate", ACTIVE_MILL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"revisionCount\":0}")
                .with(submitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            put("/api/v1/admin/mills/{id}/contacts", MILL_WITH_CONTACTS)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"headOfficeContactInd\":\"Y\",\"revisionCount\":0}")
                .with(submitter()))
        .andExpect(status().isForbidden());

    // Nothing leaked and nothing moved.
    assertEquals("ACT", statusCode(ACTIVE_MILL));
    assertTrue(xrefRow(UNTRACKED_MILL) == null || xrefRow(UNTRACKED_MILL).isEmpty());
  }

  @Test
  @DisplayName("A request whose token carries no idp username is refused before any write")
  void aTokenWithoutTheAuditUsernameIsRefused() throws Exception {
    // The converter falls back to the sub for the principal NAME, but actingUser reads the claim
    // itself and must refuse: silently stamping a 36-char sub would be the exact ORA-12899 the
    // guard exists to pre-empt. The refusal is a 500 — a broken identity contract, not a caller
    // mistake — and nothing may have been written.
    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/deactivate", ACTIVE_MILL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"revisionCount\":0}")
                .with(adminWithoutUsername()))
        .andExpect(status().isInternalServerError());

    assertEquals("ACT", statusCode(ACTIVE_MILL));
    assertEquals(0, ((Number) xrefRow(ACTIVE_MILL).get("REVISION_COUNT")).intValue());
  }

  @Test
  @DisplayName("An unknown mill is not found on every addressed operation")
  void unknownMillIsNotFound() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills/{id}", 88888L).with(admin()))
        .andExpect(status().isNotFound())
        // The resolved sentence, not the raw key: a missing bundle key would still 404 and would
        // pass a status-only assertion while shipping "mill.not.found.by.id" as user-facing text.
        .andExpect(jsonPath("$.detail").value("The selected mill could not be found."));
    mockMvc
        .perform(get("/api/v1/admin/mills/{id}/contact-options", 88888L).with(admin()))
        .andExpect(status().isNotFound());
    mockMvc
        .perform(changeStatus("/api/v1/admin/mills/{id}/activate", 88888L, 0))
        .andExpect(status().isNotFound());
    mockMvc
        .perform(changeStatus("/api/v1/admin/mills/{id}/deactivate", 88888L, 0))
        .andExpect(status().isNotFound());
  }

  @Test
  @DisplayName("An untracked ministry mill cannot be addressed until it is imported")
  void anUntrackedMillIsNotAddressable() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills/{id}", UNTRACKED_MILL).with(admin()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail").value("The selected mill could not be found."));
  }

  // ---------------------------------------------------------------- helpers

  private MockHttpServletRequestBuilder changeStatus(String path, long millId, int revisionCount) {
    return post(path, millId)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"revisionCount\":" + revisionCount + "}")
        .with(admin());
  }

  private MockHttpServletRequestBuilder saveContacts(
      long millId, String indicator, Long headOffice, Long division, Integer revisionCount) {
    StringBuilder body = new StringBuilder("{\"headOfficeContactInd\":\"").append(indicator);
    body.append("\",\"headOfficeContactId\":").append(headOffice);
    body.append(",\"divisionContactId\":").append(division);
    body.append(",\"revisionCount\":").append(revisionCount).append("}");
    return put("/api/v1/admin/mills/{id}/contacts", millId)
        .contentType(MediaType.APPLICATION_JSON)
        .content(body.toString())
        .with(admin());
  }

  private static RequestPostProcessor groups(String... groups) {
    return jwt()
        .jwt(
            j ->
                j.claim("identity_provider", "azureidir")
                    .claim("client_roles", List.of(groups))
                    .claim("idir_username", ADMIN_USERNAME)
                    .claim("idir_user_guid", "ADMIN001BBBBCCCCDDDDEEEEFFFF0001"))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private static RequestPostProcessor admin() {
    return groups("ILCR_ADMIN");
  }

  /**
   * A real admin token that carries no {@code custom:idp_username} — a broken identity contract.
   */
  private static RequestPostProcessor adminWithoutUsername() {
    return jwt()
        .jwt(
            j ->
                j.claim("identity_provider", "azureidir")
                    .claim("client_roles", List.of("ILCR_ADMIN"))
                    .claim("idir_user_guid", "ADMIN001BBBBCCCCDDDDEEEEFFFF0001"))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private static RequestPostProcessor submitter() {
    return groups("ILCR_SUBMITTER");
  }

  private Map<String, Object> xrefRow(long millId) {
    List<Map<String, Object>> rows =
        jdbcTemplate.queryForList(
            "SELECT ILCR_MILL_STATUS_CODE, HEAD_OFFICE_CONTACT_IND, HEAD_OFFICE_CONTACT_ID, "
                + "DIVISION_CONTACT_ID, COMMENTS, REVISION_COUNT, ENTRY_USERID, ENTRY_TIMESTAMP, "
                + "UPDATE_USERID, UPDATE_TIMESTAMP FROM THE.ILCR_MILL_STATUS_XREF "
                + "WHERE ILCR_MILL_STATUS_XREF_ID = ?",
            millId);
    return rows.isEmpty() ? Map.of() : rows.get(0);
  }

  private String statusCode(long millId) {
    return (String) xrefRow(millId).get("ILCR_MILL_STATUS_CODE");
  }

  private Map<String, Object> statusRow(long millId, int year) {
    return jdbcTemplate.queryForMap(
        "SELECT ILCR_MILL_REPORT_STATUS_CODE, MILL_SILVICULTUR_STATUS_CODE, REPORT_COMPLETED_IND "
            + "FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = ?",
        millId,
        year);
  }

  private int statusRowCount(long millId, int year) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID = ? "
            + "AND REPORT_YEAR = ?",
        Integer.class,
        millId,
        year);
  }

  private int categoryRowCount(long millId, int year) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE.ILCR_REPORT_CATEGORY WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = ?",
        Integer.class,
        millId,
        year);
  }

  /**
   * Seed a mill's complete current-year report-record set: the status row plus one row for every
   * one of the eleven schedule categories. This is the only enrolled shape delivery holds, so a
   * test that wants "already enrolled" must seed all twelve rows — seeding the status row alone
   * seeds a half-enrolled mill, which activation now refuses.
   *
   * <p>The status row is stamped {@code 'S'} rather than the {@code 'D'} enrolment writes, so an
   * assertion that the existing states are left alone cannot pass by coincidence.
   */
  private void seedCompleteReportRecords(long millId) {
    jdbcTemplate.update(
        "INSERT INTO THE.ILCR_MILL_REPORT_STATUS (REPORT_YEAR, ILCR_MILL_ID, "
            + "ILCR_MILL_REPORT_STATUS_CODE, MILL_SILVICULTUR_STATUS_CODE, REPORT_COMPLETED_IND, "
            + "REVISION_COUNT, ENTRY_USERID, ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP) "
            + "VALUES (?, ?, 'S', 'S', 'N', 0, 'SEED', SYSDATE, 'SEED', SYSDATE)",
        CURRENT_YEAR,
        millId);
    for (String categoryId : List.of("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11")) {
      jdbcTemplate.update(
          "INSERT INTO THE.ILCR_REPORT_CATEGORY (REPORT_YEAR, ILCR_MILL_ID, ILCR_CATEGORY_ID, "
              + "CATEGORY_STATE_CODE, REPORTABLE_DETAIL_IND, REVISION_COUNT, ENTRY_USERID, "
              + "ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP) "
              + "VALUES (?, ?, ?, 'D', 'Y', 0, 'SEED', SYSDATE, 'SEED', SYSDATE)",
          CURRENT_YEAR,
          millId,
          categoryId);
    }
  }

  private void resetMill(long millId, String statusCode) {
    jdbcTemplate.update(
        "UPDATE THE.ILCR_MILL_STATUS_XREF SET ILCR_MILL_STATUS_CODE = ?, REVISION_COUNT = 0 "
            + "WHERE ILCR_MILL_STATUS_XREF_ID = ?",
        statusCode,
        millId);
  }
}
