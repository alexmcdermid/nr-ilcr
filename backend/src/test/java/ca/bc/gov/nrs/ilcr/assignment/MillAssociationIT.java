package ca.bc.gov.nrs.ilcr.assignment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
 * Acceptance test — the mill record's association panel (UC-MILL-001 S05-S09, S13), security ON.
 * Exercises the mill-record semantics that deliberately differ from the users screen: the add
 * creates the association INACTIVE while confirming "has been activated" (the pinned legacy quirk),
 * a duplicate add warns and never revives an ended pair, and activation is blocked on a closed mill
 * with the verbatim legacy message while deactivation is never blocked at all.
 *
 * <p>Each test removes the rows it created, so the JVM-wide container stays at its seeded baseline:
 * {@code MillMaintenanceSchemaIT.fixtureBlockIsIntact} asserts mill 751 has no active assignment,
 * and this class must leave that true.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Mill-record user associations (admin-gated)")
class MillAssociationIT extends AbstractOracleIT {

  /** ACT with no seeded assignments (R__75) — the add/activate/deactivate happy paths. */
  private static final long ACTIVE_MILL = 751L;

  /**
   * CLS (R__75) — the S13 activation block. This class never changes its status, but {@code
   * MillMaintenanceIT} does: its import test activates 753 and restores it only in that class's own
   * cleanup hook. An abort before that hook leaves 753 ACT, and the S13 test would then silently
   * pass a 200 where it demands a 409 — so {@link #closedMillIsActuallyClosed()} asserts the
   * precondition rather than trusting it.
   */
  private static final long CLOSED_MILL = 753L;

  /** A MILL row with no cross-reference (R__75) — the untracked 404 case. */
  private static final long UNTRACKED_MILL = 750L;

  private static final String GUID_A = "MILLASC1BBBBCCCCDDDDEEEEFFFF0001";
  private static final String GUID_B = "MILLASC2BBBBCCCCDDDDEEEEFFFF0002";

  /** The acting administrator's {@code custom:idp_username}; synthetic, never a real person's. */
  private static final String ADMIN_USERNAME = "TESTADMN";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  @Autowired private JdbcTemplate jdbcTemplate;

  @BeforeEach
  void closedMillIsActuallyClosed() {
    // A cross-class precondition, asserted rather than assumed — see CLOSED_MILL's note. Without
    // this, a leak from MillMaintenanceIT turns the S13 refusal test into a false pass.
    assertEquals(
        "CLS",
        jdbcTemplate.queryForObject(
            "SELECT ILCR_MILL_STATUS_CODE FROM THE.ILCR_MILL_STATUS_XREF "
                + "WHERE ILCR_MILL_STATUS_XREF_ID = ?",
            String.class,
            CLOSED_MILL),
        "mill 753 must be CLS at the start of every test in this class");
  }

  @AfterEach
  void cleanUp() {
    // FK-safe order: the xref references ILCR_USER. Deleting by GUID covers every mill a test
    // touched, and restores fixtureBlockIsIntact's "751 has no active assignment" invariant.
    jdbcTemplate.update(
        "DELETE FROM THE.ILCR_MILL_USER_XREF WHERE USER_GUID IN (?, ?)", GUID_A, GUID_B);
    jdbcTemplate.update("DELETE FROM THE.ILCR_USER WHERE USER_GUID IN (?, ?)", GUID_A, GUID_B);
  }

  // ---------------------------------------------------------------- add (S05/S07)

  @Test
  @DisplayName("The add creates the association INACTIVE yet confirms 'has been activated' (S05)")
  void addCreatesTheAssociationInactiveWithTheLegacyQuirk() throws Exception {
    Timestamp startedAt = dbNow();

    mockMvc
        .perform(add(ACTIVE_MILL, GUID_A))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.assignment.userGuid").value(GUID_A))
        .andExpect(jsonPath("$.assignment.millNumber").value("7510"))
        .andExpect(jsonPath("$.assignment.status").value("ENDED"))
        .andExpect(jsonPath("$.assignment.activeDate").doesNotExist())
        .andExpect(jsonPath("$.assignment.inactiveDate").exists())
        .andExpect(jsonPath("$.assignment.revisionCount").value(0))
        .andExpect(jsonPath("$.messageKey").value("user.activate.mill"))
        // The pinned quirk, resolved text and all: the row is inactive, the sentence says
        // activated. The name positions render empty until the directory join ships.
        .andExpect(
            jsonPath("$.message")
                .value(
                    "Mill 7510 - Cariboo Maintain Mill has been activated for user "
                        + GUID_A
                        + " -  ."));

    Map<String, Object> row = xrefRow(ACTIVE_MILL, GUID_A);
    assertNull(row.get("ACTIVE_DATE"));
    assertNotNull(row.get("INACTIVE_DATE"));
    assertEquals(0, ((Number) row.get("REVISION_COUNT")).intValue());
    assertEquals(ADMIN_USERNAME, row.get("ENTRY_USERID"));
    assertEquals(ADMIN_USERNAME, row.get("UPDATE_USERID"));
    // Both columns are DATE NOT NULL, so assertNotNull alone could never fail here — compare
    // against the pre-call clock so the assertion has a failing state.
    assertStampedSince(startedAt, row.get("ENTRY_TIMESTAMP"), "ENTRY_TIMESTAMP");
    assertStampedSince(startedAt, row.get("UPDATE_TIMESTAMP"), "UPDATE_TIMESTAMP");
  }

  @Test
  @DisplayName("A first association provisions the account row INACTIVE (the ratified asymmetry)")
  void addProvisionsTheAccountInactive() throws Exception {
    mockMvc.perform(add(ACTIVE_MILL, GUID_A)).andExpect(status().isOk());

    Map<String, Object> account =
        jdbcTemplate.queryForMap(
            "SELECT ACTIVE_IND, ILCR_ROLE_NAME, REVISION_COUNT FROM THE.ILCR_USER "
                + "WHERE USER_GUID = ?",
            GUID_A);
    assertEquals("N", account.get("ACTIVE_IND"));
    assertEquals("LICENSEE", account.get("ILCR_ROLE_NAME"));
    assertEquals(0, ((Number) account.get("REVISION_COUNT")).intValue());
  }

  @Test
  @DisplayName("Adding a user already ACTIVE on the mill warns verbatim and changes nothing (S07)")
  void addWarnsOnAnActivePair() throws Exception {
    seedUser(GUID_A);
    seedAssignment(ACTIVE_MILL, GUID_A, true);

    mockMvc
        .perform(add(ACTIVE_MILL, GUID_A))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.messageKey").value("user.not.associated.to.mill"))
        .andExpect(
            jsonPath("$.message")
                .value(
                    "User "
                        + GUID_A
                        + " is already associated to mill Cariboo Maintain Mill. Please verify."));

    Map<String, Object> row = xrefRow(ACTIVE_MILL, GUID_A);
    assertNotNull(row.get("ACTIVE_DATE"));
    assertEquals(0, ((Number) row.get("REVISION_COUNT")).intValue());
    assertEquals("SEED", row.get("UPDATE_USERID"));
  }

  @Test
  @DisplayName("Adding a user with an ENDED association warns too — the pair is NOT revived")
  void addDoesNotReviveAnEndedPair() throws Exception {
    seedUser(GUID_A);
    seedAssignment(ACTIVE_MILL, GUID_A, false);

    mockMvc
        .perform(add(ACTIVE_MILL, GUID_A))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.messageKey").value("user.not.associated.to.mill"))
        .andExpect(jsonPath("$.assignment.status").value("ENDED"));

    // Still ended, untouched: reviving by re-adding is the users-screen semantic, and here it
    // would let the closed-mill activation block be sidestepped.
    //
    // THE OTHER HALF OF THIS RULE LIVES IN ANOTHER CLASS, and the pair only makes sense read
    // together: AssignmentWriteIT proves that the SAME input — an add against an ENDED pair — does
    // the OPPOSITE on the users surface, reviving the association instead of warning. Both are
    // legacy-real (the two screens genuinely disagreed, D2), so if either test is ever "fixed" to
    // match the other, the deliberate disagreement has been destroyed rather than a bug repaired.
    Map<String, Object> row = xrefRow(ACTIVE_MILL, GUID_A);
    assertNull(row.get("ACTIVE_DATE"));
    assertNotNull(row.get("INACTIVE_DATE"));
    assertEquals(0, ((Number) row.get("REVISION_COUNT")).intValue());
  }

  @Test
  @DisplayName("The add itself is not blocked by a closed mill — only activation is")
  void addWorksOnAClosedMill() throws Exception {
    mockMvc
        .perform(add(CLOSED_MILL, GUID_A))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.assignment.status").value("ENDED"));

    assertNull(xrefRow(CLOSED_MILL, GUID_A).get("ACTIVE_DATE"));
  }

  // ---------------------------------------------------------------- activate (S09/S13)

  @Test
  @DisplayName("Activation succeeds while the mill is Active and confirms verbatim (S09)")
  void activateSucceedsOnAnActiveMill() throws Exception {
    mockMvc.perform(add(ACTIVE_MILL, GUID_A)).andExpect(status().isOk());

    mockMvc
        .perform(toggle(ACTIVE_MILL, GUID_A, "activate", 0))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.assignment.status").value("ACTIVE"))
        .andExpect(jsonPath("$.assignment.revisionCount").value(1))
        .andExpect(jsonPath("$.messageKey").value("user.activate.mill"))
        .andExpect(
            jsonPath("$.message")
                .value(
                    "Mill 7510 - Cariboo Maintain Mill has been activated for user "
                        + GUID_A
                        + " -  ."));

    Map<String, Object> row = xrefRow(ACTIVE_MILL, GUID_A);
    assertNotNull(row.get("ACTIVE_DATE"));
    assertNull(row.get("INACTIVE_DATE"));
    assertEquals(1, ((Number) row.get("REVISION_COUNT")).intValue());
    assertEquals(ADMIN_USERNAME, row.get("UPDATE_USERID"));
  }

  @Test
  @DisplayName("Activation is refused on a Closed mill with the verbatim legacy message (S13)")
  void activateIsRefusedWhileTheMillIsClosed() throws Exception {
    mockMvc.perform(add(CLOSED_MILL, GUID_A)).andExpect(status().isOk());

    mockMvc
        .perform(toggle(CLOSED_MILL, GUID_A, "activate", 0))
        .andExpect(status().isConflict())
        .andExpect(
            jsonPath("$.detail").value("You must activate the mill before activating any users."));

    // The refusal leaves the association exactly as it was — including the revision, so a retry
    // after activating the mill still works with the revision the screen already holds.
    Map<String, Object> row = xrefRow(CLOSED_MILL, GUID_A);
    assertNull(row.get("ACTIVE_DATE"));
    assertNotNull(row.get("INACTIVE_DATE"));
    assertEquals(0, ((Number) row.get("REVISION_COUNT")).intValue());
  }

  @Test
  @DisplayName("Activating an already-active association is a conflict, not a re-stamp")
  void activatingAnActiveAssociationIsRefused() throws Exception {
    seedUser(GUID_A);
    seedAssignment(ACTIVE_MILL, GUID_A, true);

    mockMvc.perform(toggle(ACTIVE_MILL, GUID_A, "activate", 0)).andExpect(status().isConflict());

    assertEquals(0, ((Number) xrefRow(ACTIVE_MILL, GUID_A).get("REVISION_COUNT")).intValue());
  }

  // ---------------------------------------------------------------- deactivate (S08)

  @Test
  @DisplayName("Deactivation succeeds and confirms verbatim (S08)")
  void deactivateSucceeds() throws Exception {
    seedUser(GUID_A);
    seedAssignment(ACTIVE_MILL, GUID_A, true);
    Timestamp startedAt = dbNow();

    mockMvc
        .perform(toggle(ACTIVE_MILL, GUID_A, "deactivate", 0))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.assignment.status").value("ENDED"))
        .andExpect(jsonPath("$.messageKey").value("user.deactivate.mill"))
        .andExpect(
            jsonPath("$.message")
                .value(
                    "Mill 7510 - Cariboo Maintain Mill has been deactivated for user "
                        + GUID_A
                        + " -  ."));

    Map<String, Object> row = xrefRow(ACTIVE_MILL, GUID_A);
    assertNull(row.get("ACTIVE_DATE"));
    assertNotNull(row.get("INACTIVE_DATE"));
    assertEquals(1, ((Number) row.get("REVISION_COUNT")).intValue());
    assertEquals(ADMIN_USERNAME, row.get("UPDATE_USERID"));
    // The seed is stamped five days old, so this fails if the UPDATE stops refreshing the stamp —
    // an audit trail that silently freezes is exactly what assertNotNull could not have caught.
    assertStampedSince(startedAt, row.get("UPDATE_TIMESTAMP"), "UPDATE_TIMESTAMP");
  }

  @Test
  @DisplayName("Deactivation has no mill-status guard: it works on a Closed mill too")
  void deactivateWorksOnAClosedMill() throws Exception {
    seedUser(GUID_A);
    seedAssignment(CLOSED_MILL, GUID_A, true);

    mockMvc
        .perform(toggle(CLOSED_MILL, GUID_A, "deactivate", 0))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.assignment.status").value("ENDED"));
  }

  // ---------------------------------------------------------------- conflicts + refusals

  @Test
  @DisplayName("A stale revision is refused on both toggles without overwriting")
  void aStaleRevisionIsRefused() throws Exception {
    seedUser(GUID_A);
    seedAssignment(ACTIVE_MILL, GUID_A, true);

    mockMvc.perform(toggle(ACTIVE_MILL, GUID_A, "deactivate", 7)).andExpect(status().isConflict());

    Map<String, Object> row = xrefRow(ACTIVE_MILL, GUID_A);
    assertNotNull(row.get("ACTIVE_DATE"));
    assertEquals(0, ((Number) row.get("REVISION_COUNT")).intValue());

    // The activate half, against a real database rather than a stubbed row count. This is the only
    // thing that proves reactivateAssignment's `AND REVISION_COUNT = :revisionCount` predicate is
    // actually in the UPDATE: drop it and the row below reactivates on a revision nobody read.
    jdbcTemplate.update(
        "UPDATE THE.ILCR_MILL_USER_XREF SET ACTIVE_DATE = NULL, INACTIVE_DATE = SYSDATE "
            + "WHERE ILCR_MILL_ID = ? AND USER_GUID = ?",
        ACTIVE_MILL,
        GUID_A);

    mockMvc.perform(toggle(ACTIVE_MILL, GUID_A, "activate", 7)).andExpect(status().isConflict());

    Map<String, Object> afterActivate = xrefRow(ACTIVE_MILL, GUID_A);
    assertNull(afterActivate.get("ACTIVE_DATE"), "a stale activate must not revive the row");
    assertNotNull(afterActivate.get("INACTIVE_DATE"));
    assertEquals(0, ((Number) afterActivate.get("REVISION_COUNT")).intValue());
  }

  @Test
  @DisplayName("A malformed userGuid on a toggle is a 400 at the boundary, not an ambiguous 404")
  void aMalformedUserGuidIsRejected() throws Exception {
    // The add body enforces exactly 32 characters so a wrong identifier cannot reach the database;
    // the path variable carries the same contract, or a truncated guid comes back as "no such
    // assignment" and an operator debugging it is looking for the wrong problem.
    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/users/{guid}/activate", ACTIVE_MILL, "TOOSHORT")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"revisionCount\":0}")
                .with(admin()))
        .andExpect(status().isBadRequest());
    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/users/{guid}/deactivate", ACTIVE_MILL, GUID_A + "X")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"revisionCount\":0}")
                .with(admin()))
        .andExpect(status().isBadRequest());
  }

  @Test
  @DisplayName("A body omitting the revision is rejected rather than treated as revision 0")
  void togglesRequireTheRevision() throws Exception {
    seedUser(GUID_A);
    seedAssignment(ACTIVE_MILL, GUID_A, false);

    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/users/{guid}/activate", ACTIVE_MILL, GUID_A)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(admin()))
        .andExpect(status().isBadRequest());
  }

  @Test
  @DisplayName("A pair with no association row is not found on both toggles")
  void aMissingAssociationIsNotFound() throws Exception {
    mockMvc
        .perform(toggle(ACTIVE_MILL, GUID_A, "activate", 0))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail").value("The requested mill assignment could not be found."));
    mockMvc.perform(toggle(ACTIVE_MILL, GUID_A, "deactivate", 0)).andExpect(status().isNotFound());
  }

  @Test
  @DisplayName("An unknown or untracked mill is not found on every operation")
  void unknownAndUntrackedMillsAreNotFound() throws Exception {
    mockMvc
        .perform(get("/api/v1/admin/mills/{id}/users", 88888L).with(admin()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail").value("The selected mill could not be found."));
    mockMvc.perform(add(UNTRACKED_MILL, GUID_A)).andExpect(status().isNotFound());
    // Both toggles, and both asserting the mill 404 rather than the association 404 — they are the
    // same status with different diagnoses, and only the detail tells an operator which one it is.
    mockMvc
        .perform(toggle(UNTRACKED_MILL, GUID_A, "activate", 0))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail").value("The selected mill could not be found."));
    mockMvc
        .perform(toggle(UNTRACKED_MILL, GUID_A, "deactivate", 0))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail").value("The selected mill could not be found."));
  }

  // ---------------------------------------------------------------- list

  @Test
  @DisplayName("The panel list carries both states by default and narrows on request")
  void listCarriesBothStatesByDefault() throws Exception {
    seedUser(GUID_A);
    seedUser(GUID_B);
    // The ENDED row is seeded on the ALPHABETICALLY FIRST guid on purpose. findByMill orders
    // active-first, then COALESCE(ACTIVE_DATE, INACTIVE_DATE) DESC, then USER_GUID — and both rows
    // are stamped within the same Oracle second, so the date term ties and USER_GUID decides. With
    // the active row on GUID_A this assertion would pass even with the active-first term deleted;
    // with it on GUID_B, only the active-first term can put GUID_B at $[0].
    seedAssignment(ACTIVE_MILL, GUID_A, false);
    seedAssignment(ACTIVE_MILL, GUID_B, true);

    mockMvc
        .perform(get("/api/v1/admin/mills/{id}/users", ACTIVE_MILL).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(2))
        // Active first — the shipped ordering, load-bearing against the guid tiebreak.
        .andExpect(jsonPath("$[0].userGuid").value(GUID_B))
        .andExpect(jsonPath("$[0].status").value("ACTIVE"))
        .andExpect(jsonPath("$[1].userGuid").value(GUID_A))
        .andExpect(jsonPath("$[1].status").value("ENDED"))
        .andExpect(jsonPath("$[0].millNumber").value("7510"));

    mockMvc
        .perform(
            get("/api/v1/admin/mills/{id}/users", ACTIVE_MILL)
                .param("includeEnded", "false")
                .with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(1))
        .andExpect(jsonPath("$[0].userGuid").value(GUID_B));
  }

  // ---------------------------------------------------------------- authorization

  @Test
  @DisplayName("A submitter is denied every operation, as a ProblemDetail, with nothing readable")
  void submitterIsDeniedEveryOperation() throws Exception {
    // Seeded FIRST, and that is the point of the test rather than a detail of it: with no row on
    // the mill, the GET has nothing to leak and both toggles would 404 on a missing association
    // even with @PreAuthorize removed — so the "nothing moved" assertion below would hold against
    // a completely ungated controller. An ACTIVE row makes every one of the four calls capable of
    // doing real damage if the gate is gone.
    seedUser(GUID_A);
    seedAssignment(ACTIVE_MILL, GUID_A, true);

    mockMvc
        .perform(get("/api/v1/admin/mills/{id}/users", ACTIVE_MILL).with(submitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
        .andExpect(jsonPath("$.status").value(403))
        .andExpect(jsonPath("$.detail").exists());
    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/users", ACTIVE_MILL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userGuid\":\"" + GUID_B + "\"}")
                .with(submitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
        .andExpect(jsonPath("$.status").value(403));
    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/users/{guid}/activate", ACTIVE_MILL, GUID_A)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"revisionCount\":0}")
                .with(submitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
        .andExpect(jsonPath("$.status").value(403));
    mockMvc
        .perform(
            post("/api/v1/admin/mills/{id}/users/{guid}/deactivate", ACTIVE_MILL, GUID_A)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"revisionCount\":0}")
                .with(submitter()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
        .andExpect(jsonPath("$.status").value(403));

    // Nothing moved: the seeded row is untouched (the deactivate would have ended it) and the add
    // created nothing for GUID_B.
    Map<String, Object> row = xrefRow(ACTIVE_MILL, GUID_A);
    assertNotNull(row.get("ACTIVE_DATE"));
    assertNull(row.get("INACTIVE_DATE"));
    assertEquals(0, ((Number) row.get("REVISION_COUNT")).intValue());
    assertEquals("SEED", row.get("UPDATE_USERID"));
    assertEquals(
        0,
        jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM THE.ILCR_MILL_USER_XREF WHERE USER_GUID = ?",
            Integer.class,
            GUID_B));
  }

  // ---------------------------------------------------------------- helpers

  private MockHttpServletRequestBuilder add(long millId, String userGuid) {
    return post("/api/v1/admin/mills/{id}/users", millId)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"userGuid\":\"" + userGuid + "\"}")
        .with(admin());
  }

  private MockHttpServletRequestBuilder toggle(
      long millId, String userGuid, String action, int revisionCount) {
    return post("/api/v1/admin/mills/{id}/users/{guid}/" + action, millId, userGuid)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"revisionCount\":" + revisionCount + "}")
        .with(admin());
  }

  private void seedUser(String userGuid) {
    jdbcTemplate.update(
        "INSERT INTO THE.ILCR_USER (USER_GUID, ILCR_ROLE_NAME, ACTIVE_IND, REVISION_COUNT, "
            + "ENTRY_USERID, ENTRY_TIMESTAMP, UPDATE_USERID, UPDATE_TIMESTAMP) "
            + "VALUES (?, 'LICENSEE', 'N', 0, 'SEED', SYSDATE, 'SEED', SYSDATE)",
        userGuid);
  }

  /**
   * Seed one association. The audit timestamps are stamped five days OLD deliberately: the toggles
   * are supposed to refresh {@code UPDATE_TIMESTAMP}, and a seed stamped {@code SYSDATE} sits in
   * the same Oracle second as the write under test, so no assertion could tell a refreshed stamp
   * from a frozen one. Five days back makes {@link #assertStampedSince} a real check.
   */
  private void seedAssignment(long millId, String userGuid, boolean active) {
    jdbcTemplate.update(
        "INSERT INTO THE.ILCR_MILL_USER_XREF (ILCR_MILL_ID, USER_GUID, ACTIVE_DATE, "
            + "INACTIVE_DATE, REVISION_COUNT, ENTRY_USERID, ENTRY_TIMESTAMP, UPDATE_USERID, "
            + "UPDATE_TIMESTAMP) VALUES (?, ?, "
            + (active ? "SYSDATE, NULL" : "NULL, SYSDATE")
            + ", 0, 'SEED', SYSDATE - 5, 'SEED', SYSDATE - 5)",
        millId,
        userGuid);
  }

  /** The database's own clock, so the comparison never straddles a JVM/container time skew. */
  private Timestamp dbNow() {
    return jdbcTemplate.queryForObject("SELECT SYSDATE FROM DUAL", Timestamp.class);
  }

  private void assertStampedSince(Timestamp since, Object stamped, String what) {
    assertNotNull(stamped, what + " must be stamped");
    assertFalse(((Timestamp) stamped).before(since), what + " must be refreshed by the write");
  }

  private Map<String, Object> xrefRow(long millId, String userGuid) {
    return jdbcTemplate.queryForMap(
        "SELECT ACTIVE_DATE, INACTIVE_DATE, REVISION_COUNT, ENTRY_USERID, ENTRY_TIMESTAMP, "
            + "UPDATE_USERID, UPDATE_TIMESTAMP FROM THE.ILCR_MILL_USER_XREF "
            + "WHERE ILCR_MILL_ID = ? AND USER_GUID = ?",
        millId,
        userGuid);
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

  private static RequestPostProcessor submitter() {
    return groups("ILCR_SUBMITTER");
  }
}
