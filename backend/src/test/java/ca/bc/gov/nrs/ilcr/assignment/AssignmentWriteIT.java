package ca.bc.gov.nrs.ilcr.assignment;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
 * Acceptance test — licensee accounts and mill assignments (UC-USR-001/002), security ON. Runs the
 * real cognito:groups → role → action path, so the ADMIN-only gate, the verbatim legacy messages
 * and the audit-column discipline are all exercised as a caller meets them.
 *
 * <p>Each test cleans up the rows it created so the JVM-wide container stays at its seeded baseline
 * for other IT classes.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Licensee accounts and mill assignments (admin-gated, Story 2.2)")
class AssignmentWriteIT extends AbstractOracleIT {

  /** A seeded ACT mill-status cross-reference id. */
  private static final long ACTIVE_MILL = 514L;

  /** A second seeded ACT mill, used for the multi-mill and closed-mill cases. */
  private static final long OTHER_ACTIVE_MILL = 522L;

  /**
   * A mill this class creates with a status xref but NO {@code ILCR_MILL_REPORT_STATUS} row — so it
   * can hold an assignment (the FK needs only the status xref) while being invisible to the
   * selectable-mill lookup.
   */
  private static final long ORPHAN_MILL = 99801L;

  // Exactly 32 characters, the width the directory GUID column and the request validation both
  // enforce; a 31-character fixture is rejected at the boundary, not by the database.
  private static final String GUID = "WRITEIT1BBBBCCCCDDDDEEEEFFFF0001";
  private static final String GUID_B = "WRITEIT2BBBBCCCCDDDDEEEEFFFF0002";

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
    jdbcTemplate.update(
        "DELETE FROM THE.ILCR_MILL_USER_XREF WHERE USER_GUID IN (?, ?)", GUID, GUID_B);
    jdbcTemplate.update("DELETE FROM THE.ILCR_USER WHERE USER_GUID IN (?, ?)", GUID, GUID_B);
    jdbcTemplate.update(
        "UPDATE THE.ILCR_MILL_STATUS_XREF SET ILCR_MILL_STATUS_CODE = 'ACT'"
            + " WHERE ILCR_MILL_STATUS_XREF_ID = ?",
        OTHER_ACTIVE_MILL);
    jdbcTemplate.update(
        "DELETE FROM THE.ILCR_MILL_STATUS_XREF WHERE ILCR_MILL_STATUS_XREF_ID = ?", ORPHAN_MILL);
    jdbcTemplate.update("DELETE FROM THE.MILL WHERE MILL_ID = ?", ORPHAN_MILL);
  }

  @Test
  @DisplayName("a first assignment provisions the account INACTIVE and the assignment ACTIVE")
  void firstAssignmentProvisionsAccountInactive() throws Exception {
    mockMvc
        .perform(assign(ACTIVE_MILL, GUID))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.messageKey").value("user.activate.mill"))
        // The resolved text is pinned, not just the key: the mill leads and the user follows, and
        // the arg orders are documented as non-interchangeable — a swap must fail here.
        .andExpect(jsonPath("$.message").value(startsWith("Mill ")))
        .andExpect(
            jsonPath("$.message").value(containsString("has been activated for user " + GUID)))
        .andExpect(jsonPath("$.assignment.status").value("ACTIVE"))
        .andExpect(jsonPath("$.assignment.activeDate").exists())
        .andExpect(jsonPath("$.assignment.inactiveDate").doesNotExist());

    // The account exists but sits at 'N' while its holder can report — the legacy asymmetry, which
    // must survive rather than being tidied into 'Y'.
    assertEquals("N", accountFlag(GUID));
    assertEquals("LICENSEE", accountRole(GUID));
  }

  @Test
  @DisplayName("writes stamp the acting administrator's raw username on every audit column")
  void writesStampEveryAuditColumn() throws Exception {
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());

    Map<String, Object> xref =
        jdbcTemplate.queryForMap(
            """
            SELECT REVISION_COUNT, ENTRY_USERID, ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP
              FROM THE.ILCR_MILL_USER_XREF WHERE ILCR_MILL_ID = ? AND USER_GUID = ?
            """,
            ACTIVE_MILL,
            GUID);
    xref.forEach((column, value) -> assertNotNull(value, column + " must be stamped"));
    // The raw claim, not the provider-prefixed form, which would not fit the column.
    assertEquals(ADMIN_USERNAME, xref.get("ENTRY_USERID"));
    assertEquals(ADMIN_USERNAME, xref.get("UPDATE_USERID"));

    Map<String, Object> account =
        jdbcTemplate.queryForMap(
            """
            SELECT REVISION_COUNT, ENTRY_USERID, ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP
              FROM THE.ILCR_USER WHERE USER_GUID = ?
            """,
            GUID);
    account.forEach((column, value) -> assertNotNull(value, column + " must be stamped"));
    assertEquals(ADMIN_USERNAME, account.get("ENTRY_USERID"));
  }

  @Test
  @DisplayName("re-assigning an already-active pair warns and changes nothing")
  void duplicateAssignmentWarns() throws Exception {
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());

    mockMvc
        .perform(assign(ACTIVE_MILL, GUID))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.messageKey").value("user.not.associated.to.mill"))
        .andExpect(jsonPath("$.message").value(containsString("is already associated to mill")))
        .andExpect(jsonPath("$.assignment.status").value("ACTIVE"));

    // Still one row, still on its original revision: the warning path wrote nothing.
    assertEquals(1, assignmentRowCount(GUID));
    assertEquals(0, assignmentRevision(ACTIVE_MILL, GUID));
  }

  @Test
  @DisplayName("ending an assignment clears the active date and keeps the row")
  void endClearsActiveDateAndKeepsRow() throws Exception {
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());

    mockMvc
        .perform(end(ACTIVE_MILL, GUID, 0))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.messageKey").value("user.deactivate.mill"))
        .andExpect(jsonPath("$.message").value(startsWith("Mill ")))
        .andExpect(
            jsonPath("$.message").value(containsString("has been deactivated for user " + GUID)))
        .andExpect(jsonPath("$.assignment.status").value("ENDED"))
        .andExpect(jsonPath("$.assignment.inactiveDate").exists())
        // The contract promises an ended assignment has no active date and no database constraint
        // enforces it, so the write must — this is what proves it.
        .andExpect(jsonPath("$.assignment.activeDate").doesNotExist());

    assertEquals(1, assignmentRowCount(GUID));
    assertNull(
        jdbcTemplate
            .queryForMap(
                "SELECT ACTIVE_DATE FROM THE.ILCR_MILL_USER_XREF"
                    + " WHERE ILCR_MILL_ID = ? AND USER_GUID = ?",
                ACTIVE_MILL,
                GUID)
            .get("ACTIVE_DATE"));
  }

  @Test
  @DisplayName("re-assigning an ended pair revives the same row rather than adding one")
  void reassignRevivesTheSameRow() throws Exception {
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());
    mockMvc.perform(end(ACTIVE_MILL, GUID, 0)).andExpect(status().isOk());

    mockMvc
        .perform(assign(ACTIVE_MILL, GUID))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.messageKey").value("user.activate.mill"))
        .andExpect(jsonPath("$.assignment.status").value("ACTIVE"))
        .andExpect(jsonPath("$.assignment.inactiveDate").doesNotExist());

    assertEquals(1, assignmentRowCount(GUID));
  }

  @Test
  @DisplayName("ending with a stale revision is refused as a conflict")
  void staleRevisionOnEndIsRefused() throws Exception {
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());
    mockMvc.perform(end(ACTIVE_MILL, GUID, 0)).andExpect(status().isOk());

    // Revision 0 was consumed by the end above, so replaying it is a lost update.
    mockMvc.perform(end(ACTIVE_MILL, GUID, 0)).andExpect(status().isConflict());
  }

  @Test
  @DisplayName("ending an assignment that was never made answers not-found")
  void endingAnUnassignedPairIsNotFound() throws Exception {
    mockMvc.perform(end(ACTIVE_MILL, GUID, 0)).andExpect(status().isNotFound());
  }

  @Test
  @DisplayName("re-ending an already-ended assignment is refused, preserving the end date")
  void reEndingAnEndedAssignmentIsRefused() throws Exception {
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());
    mockMvc.perform(end(ACTIVE_MILL, GUID, 0)).andExpect(status().isOk());

    // Even with the CURRENT revision (1, after the end above): the row is already ended, and
    // re-stamping would silently overwrite the historical end date on an audit-bearing table.
    mockMvc.perform(end(ACTIVE_MILL, GUID, 1)).andExpect(status().isConflict());
    assertEquals(1, assignmentRevision(ACTIVE_MILL, GUID));
  }

  @Test
  @DisplayName("an assignment on a mill with no report-status enrollment can still be ended")
  void endingOnAnUnenrolledMillWorks() throws Exception {
    // A mill with a status xref (so the assignment FK holds) but no ILCR_MILL_REPORT_STATUS row —
    // invisible to the selectable-mill lookup, exactly the shape legacy delivery data can hold.
    jdbcTemplate.update(
        "INSERT INTO THE.MILL (MILL_ID, MILL_NAME, MILL_NUMBER, ENTRY_USERID)"
            + " VALUES (?, 'Orphan Mill', 99801, 'SEED')",
        ORPHAN_MILL);
    jdbcTemplate.update(
        "INSERT INTO THE.ILCR_MILL_STATUS_XREF"
            + " (ILCR_MILL_STATUS_XREF_ID, ILCR_MILL_STATUS_CODE, ENTRY_USERID)"
            + " VALUES (?, 'ACT', 'SEED')",
        ORPHAN_MILL);
    mockMvc.perform(setActive(GUID, true)).andExpect(status().isOk());
    jdbcTemplate.update(
        "INSERT INTO THE.ILCR_MILL_USER_XREF (ILCR_MILL_ID, USER_GUID, ACTIVE_DATE, REVISION_COUNT,"
            + " ENTRY_USERID, ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP)"
            + " VALUES (?, ?, SYSDATE, 0, 'SEED', SYSDATE, 'SEED', SYSDATE)",
        ORPHAN_MILL,
        GUID);

    // The end must key off the assignment row, not the selectable-mill lookup — otherwise this
    // assignment could never be ended and the deactivation guard below could never be satisfied.
    mockMvc
        .perform(end(ORPHAN_MILL, GUID, 0))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.assignment.status").value("ENDED"));

    mockMvc.perform(setActive(GUID, false)).andExpect(status().isOk());
  }

  @Test
  @DisplayName("listing or ending against a mill that does not exist answers not-found")
  void operationsOnAnUnknownMillAreNotFound() throws Exception {
    mockMvc
        .perform(get("/api/v1/mills/{millId}/submitters", 999_999L).with(admin()))
        .andExpect(status().isNotFound());
    mockMvc.perform(end(999_999L, GUID, 0)).andExpect(status().isNotFound());
  }

  @Test
  @DisplayName("an end body that omits the revision is rejected rather than treated as zero")
  void emptyEndBodyIsRejected() throws Exception {
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());

    mockMvc
        .perform(
            patch("/api/v1/mills/{millId}/submitters/{userGuid}", ACTIVE_MILL, GUID)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(admin()))
        .andExpect(status().isBadRequest());
  }

  @Test
  @DisplayName("deactivating a user who has no account answers not-found and creates nothing")
  void deactivatingAMissingAccountIsNotFound() throws Exception {
    mockMvc
        .perform(setActive(GUID, false))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail").value("The requested user account could not be found."));

    // No phantom account: a mistyped GUID must not mint an inactive ILCR_USER row.
    assertEquals(0, accountRowCount(GUID));
  }

  @Test
  @DisplayName("reviving an assignment on a closed mill is refused with the legacy message")
  void revivingOnAClosedMillIsRefused() throws Exception {
    mockMvc.perform(assign(OTHER_ACTIVE_MILL, GUID)).andExpect(status().isOk());
    mockMvc.perform(end(OTHER_ACTIVE_MILL, GUID, 0)).andExpect(status().isOk());
    closeMill(OTHER_ACTIVE_MILL);

    mockMvc
        .perform(assign(OTHER_ACTIVE_MILL, GUID))
        .andExpect(status().isConflict())
        .andExpect(
            jsonPath("$.detail").value("You must activate the mill before activating any users."));
  }

  @Test
  @DisplayName("account activation of a directory user with no account creates it ACTIVE")
  void firstActivationCreatesTheAccountActive() throws Exception {
    mockMvc
        .perform(setActive(GUID, true))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.messageKey").value("user.activated"))
        // Formatted, with the GUID in the user position: "User {0} - {1} {2} has been activated."
        .andExpect(jsonPath("$.message").value(startsWith("User " + GUID)))
        .andExpect(jsonPath("$.message").value(containsString("has been activated")))
        .andExpect(jsonPath("$.account.activeInd").value("Y"));

    // The opposite of what a first assignment does — the legacy asymmetry, not an oversight.
    assertEquals("Y", accountFlag(GUID));
  }

  @Test
  @DisplayName("deactivation is refused while any assignment is active, leaving the flag untouched")
  void deactivationBlockedByAnActiveAssignment() throws Exception {
    mockMvc.perform(setActive(GUID, true)).andExpect(status().isOk());
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());

    mockMvc
        .perform(setActive(GUID, false))
        .andExpect(status().isConflict())
        // The whole point of these two assertions is that the message is FORMATTED: the user is
        // named, and the legacy doubled '' escapes have collapsed to single quotes. A key resolved
        // without arguments would ship "User {0}" and "''Active''" straight to the screen.
        .andExpect(jsonPath("$.detail").value(containsString(GUID)))
        .andExpect(
            jsonPath("$.detail")
                .value(
                    containsString(
                        "has an 'Active' 'User To Mill Status' on one or more 'Associated Mills'")))
        .andExpect(
            jsonPath("$.detail")
                .value(
                    containsString(
                        "must be set to 'Inactive' before deactivation of this user is"
                            + " permitted")));

    assertEquals("Y", accountFlag(GUID));
  }

  @Test
  @DisplayName("deactivation succeeds once every assignment has been ended")
  void deactivationSucceedsWithNoActiveAssignments() throws Exception {
    mockMvc.perform(setActive(GUID, true)).andExpect(status().isOk());
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());
    mockMvc.perform(end(ACTIVE_MILL, GUID, 0)).andExpect(status().isOk());

    mockMvc
        .perform(setActive(GUID, false))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.messageKey").value("user.inactivated"))
        .andExpect(jsonPath("$.account.activeInd").value("N"));
  }

  @Test
  @DisplayName("a mill's list carries the joined mill number and name, ended rows only on request")
  void listByMillJoinsTheMillAndHidesEndedByDefault() throws Exception {
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());
    mockMvc.perform(assign(ACTIVE_MILL, GUID_B)).andExpect(status().isOk());
    mockMvc.perform(end(ACTIVE_MILL, GUID_B, 0)).andExpect(status().isOk());

    mockMvc
        .perform(get("/api/v1/mills/{millId}/submitters", ACTIVE_MILL).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[?(@.userGuid=='" + GUID + "')]").exists())
        .andExpect(jsonPath("$[?(@.userGuid=='" + GUID_B + "')]").doesNotExist())
        .andExpect(jsonPath("$[?(@.userGuid=='" + GUID + "')].millName").exists());

    mockMvc
        .perform(
            get("/api/v1/mills/{millId}/submitters", ACTIVE_MILL)
                .param("includeEnded", "true")
                .with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[?(@.userGuid=='" + GUID_B + "')]").exists());
  }

  @Test
  @DisplayName("one submitter holds dated assignments on several mills, ended only on request")
  void aSubmitterHoldsSeveralAssignments() throws Exception {
    mockMvc.perform(assign(ACTIVE_MILL, GUID)).andExpect(status().isOk());
    mockMvc.perform(assign(OTHER_ACTIVE_MILL, GUID)).andExpect(status().isOk());
    mockMvc.perform(end(OTHER_ACTIVE_MILL, GUID, 0)).andExpect(status().isOk());

    // The user-side list applies the same ended-rows filter as the mill-side one.
    mockMvc
        .perform(get("/api/v1/submitters/{userGuid}/mills", GUID).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(1))
        .andExpect(jsonPath("$[0].millId").value(ACTIVE_MILL))
        .andExpect(jsonPath("$[0].activeDate").exists());

    mockMvc
        .perform(
            get("/api/v1/submitters/{userGuid}/mills", GUID)
                .param("includeEnded", "true")
                .with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(2))
        .andExpect(jsonPath("$[0].millId").value(ACTIVE_MILL))
        .andExpect(jsonPath("$[1].millId").value(OTHER_ACTIVE_MILL));
  }

  @Test
  @DisplayName("assigning to a mill that does not exist answers not-found")
  void assigningToAnUnknownMillIsNotFound() throws Exception {
    mockMvc.perform(assign(999_999L, GUID)).andExpect(status().isNotFound());
  }

  @Test
  @DisplayName("a body that omits the flag is rejected rather than read as a deactivation")
  void emptyAccountBodyIsRejected() throws Exception {
    mockMvc
        .perform(
            patch("/api/v1/submitters/{userGuid}", GUID)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(admin()))
        .andExpect(status().isBadRequest());

    // Nothing was created, which is the point: a body that says nothing must not switch an account
    // off by default.
    assertEquals(0, accountRowCount(GUID));
  }

  @Test
  @DisplayName("a blank or wrong-length GUID is rejected before it reaches the database")
  void malformedGuidIsRejected() throws Exception {
    mockMvc.perform(assign(ACTIVE_MILL, "   ")).andExpect(status().isBadRequest());
    mockMvc.perform(assign(ACTIVE_MILL, "TOOSHORT")).andExpect(status().isBadRequest());
  }

  @Test
  @DisplayName("a submitter is denied every assignment and account operation")
  void submitterIsDeniedEveryOperation() throws Exception {
    mockMvc
        .perform(get("/api/v1/mills/{millId}/submitters", ACTIVE_MILL).with(submitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(get("/api/v1/submitters/{userGuid}/mills", GUID).with(submitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            post("/api/v1/mills/{millId}/submitters", ACTIVE_MILL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userGuid\":\"" + GUID + "\"}")
                .with(submitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            patch("/api/v1/mills/{millId}/submitters/{userGuid}", ACTIVE_MILL, GUID)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"revisionCount\":0}")
                .with(submitter()))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            patch("/api/v1/submitters/{userGuid}", GUID)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"active\":true}")
                .with(submitter()))
        .andExpect(status().isForbidden());

    assertEquals(0, accountRowCount(GUID));
  }

  private MockHttpServletRequestBuilder assign(long millId, String userGuid) {
    return post("/api/v1/mills/{millId}/submitters", millId)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"userGuid\":\"" + userGuid + "\"}")
        .with(admin());
  }

  private MockHttpServletRequestBuilder end(long millId, String userGuid, int revision) {
    return patch("/api/v1/mills/{millId}/submitters/{userGuid}", millId, userGuid)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"revisionCount\":" + revision + "}")
        .with(admin());
  }

  private MockHttpServletRequestBuilder setActive(String userGuid, boolean active) {
    return patch("/api/v1/submitters/{userGuid}", userGuid)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"active\":" + active + "}")
        .with(admin());
  }

  private RequestPostProcessor admin() {
    return groups("ILCR_ADMIN");
  }

  private RequestPostProcessor submitter() {
    return groups("ILCR_SUBMITTER");
  }

  private RequestPostProcessor groups(String... groups) {
    return jwt()
        .jwt(
            j ->
                j.claim("identity_provider", "azureidir")
                    .claim("client_roles", List.of(groups))
                    .claim("idir_username", ADMIN_USERNAME)
                    .claim("idir_user_guid", "ADMIN001BBBBCCCCDDDDEEEEFFFF0001"))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private void closeMill(long millStatusXrefId) {
    jdbcTemplate.update(
        "UPDATE THE.ILCR_MILL_STATUS_XREF SET ILCR_MILL_STATUS_CODE = 'CLS'"
            + " WHERE ILCR_MILL_STATUS_XREF_ID = ?",
        millStatusXrefId);
  }

  private String accountFlag(String userGuid) {
    return jdbcTemplate.queryForObject(
        "SELECT ACTIVE_IND FROM THE.ILCR_USER WHERE USER_GUID = ?", String.class, userGuid);
  }

  private String accountRole(String userGuid) {
    return jdbcTemplate.queryForObject(
        "SELECT ILCR_ROLE_NAME FROM THE.ILCR_USER WHERE USER_GUID = ?", String.class, userGuid);
  }

  private int accountRowCount(String userGuid) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE.ILCR_USER WHERE USER_GUID = ?", Integer.class, userGuid);
  }

  private int assignmentRowCount(String userGuid) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM THE.ILCR_MILL_USER_XREF WHERE USER_GUID = ?",
        Integer.class,
        userGuid);
  }

  private int assignmentRevision(long millId, String userGuid) {
    return jdbcTemplate.queryForObject(
        "SELECT REVISION_COUNT FROM THE.ILCR_MILL_USER_XREF"
            + " WHERE ILCR_MILL_ID = ? AND USER_GUID = ?",
        Integer.class,
        millId,
        userGuid);
  }
}
