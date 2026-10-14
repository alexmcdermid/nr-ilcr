package ca.bc.gov.nrs.ilcr.schedule11;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;

/**
 * Acceptance test — Story 26.2 AC 2/4/5/6/8/9: the ministry corrects a Submitted Schedule 11 on the
 * Licensee's own page, through the page-level save, and no track moves. Security ON: the admin's
 * authorities come through the production {@link FamJwtAuthenticationConverter}. The test
 * post-processor names the token from its {@code sub} rather than the converter's {@code
 * custom:idp_username}, so both carry the one audit name the write must stamp.
 *
 * <p>Fixtures ({@code R__58}): 802 is written, by one test that runs the whole correction story in
 * order (so JUnit's method order cannot split it); 803, 804 and 805 are never written — every arm
 * on them refuses, and "nothing written" is proven by reading the rows before and after; 806
 * (silviculture {@code D}) is written only by the Licensee-at-Draft arm. On every mill but 806 the
 * silviculture track is {@code S} while Schedules 1–10 are {@code D}: a write that reached the
 * wrong track's status or categories shows here instead of coinciding with the right answer.
 *
 * <p><strong>The echoed {@code trackStatus} is not evidence the status did not move</strong> — it
 * is the gate's own pre-write read. The status row and the category rows are READ, before and
 * after.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Schedule 11 — ministry correction at Submitted (Story 26.2)")
class Schedule11CorrectionIT extends Schedule11CorrectionSupport {

  @Test
  @DisplayName(
      "AC 4 + CHK-011 S07: admin at S adds, then bulk-saves an edit and a delete, twice — rows"
          + " written, no track moved, no audit row written, and the original stays the Licensee's")
  void correctionAtSubmitted_movesNoTrack_andKeepsTheSubmittedBaseline() throws Exception {
    Map<String, Object> statusBefore = statusRow(802);
    List<Map<String, Object>> categoriesBefore = categories(802);
    String auditBefore = auditTables();
    assertThat(statusBefore.get("MILL_SILVICULTUR_STATUS_CODE")).isEqualTo("S");
    assertThat(statusBefore.get("ILCR_MILL_REPORT_STATUS_CODE")).isEqualTo("D");

    JsonNode served = document(802, admin());
    assertThat(served.get("editable").asBoolean()).as("admin may write at S (16.1)").isTrue();
    assertThat(served.get("trackStatus").asText()).isEqualTo("S");

    // Add persists at once, as legacy's addLocation() -> save(true) did.
    mockMvc
        .perform(
            post(LOCATIONS)
                .with(csrf())
                .param("millId", "802")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"location":"Ministry Added","enhancedIndicator":false,
                     "biogeoclimaticCatalogueId":8803,"netArea":3,"actualCost":100}
                    """)
                .with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message.text", is(SAVED)));

    // 9423 takes over 9424's biogeo+location ('Delete Me', 8802) in the SAME save that deletes
    // 9424.
    // Valid as a whole; it passes only because the deletes run first, against the live
    // BSRPT_BSRPT_UK_UK (the clash arm below proves the constraint is enforced here).
    int rev = revision(9423);
    mockMvc
        .perform(
            save(802, saveBody(item(9423, fields("Delete Me", 8802, "21", "1100", rev)), "9424"))
                .with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message.key", is("dataSavedSuccesfullyInfoMsg")))
        .andExpect(jsonPath("$.message.text", is(SAVED)))
        .andExpect(jsonPath("$.trackStatus", is("S")))
        .andExpect(jsonPath("$.editable", is(true)))
        .andExpect(jsonPath("$.locations[?(@.locationId==9424)]", hasSize(0)));

    Map<String, Object> row =
        jdbc.queryForMap(
            "SELECT LOCATION, BECBIOGEOCLIMATIC_CATALOGUE_ID, REVISION_COUNT, UPDATE_USERID"
                + " FROM THE.BASIC_SILVICULTURE_REPORT WHERE BASIC_SILVICULTURE_REPORT_ID = 9423");
    assertThat(row.get("LOCATION")).isEqualTo("Delete Me");
    assertThat(((Number) row.get("BECBIOGEOCLIMATIC_CATALOGUE_ID")).longValue()).isEqualTo(8802L);
    assertThat(((Number) row.get("REVISION_COUNT")).intValue()).isEqualTo(rev + 1);
    assertThat(row.get("UPDATE_USERID")).isEqualTo(ADMIN_NAME);
    assertThat(
            jdbc.queryForObject(
                "SELECT COUNT(*) FROM THE.BASIC_SILVICULTURE_REPORT"
                    + " WHERE BASIC_SILVICULTURE_REPORT_ID = 9424",
                Integer.class))
        .isZero();
    assertThat(
            jdbc.queryForObject(
                "SELECT COUNT(*) FROM THE.ILCR_COST_REPORT_DETAIL"
                    + " WHERE BASIC_SILVICULTURE_REPORT_ID = 9424",
                Integer.class))
        .as("the deleted location's whole cost family goes with it")
        .isZero();

    // A second correction of the same fields (CHK-011 S07).
    mockMvc
        .perform(
            save(802, saveBody(item(9423, fields("Second Fix", 8801, "22", "1200", rev + 1)), ""))
                .with(admin()))
        .andExpect(status().isOk());

    // No track moved, value for value, and no audit row was written by the application.
    assertThat(statusRow(802)).isEqualTo(statusBefore);
    assertThat(categories(802)).isEqualTo(categoriesBefore);
    assertThat(auditTables()).as("the application never writes *_AUD rows").isEqualTo(auditBefore);

    // So the baseline is still the Licensee's submission, however many corrections landed.
    JsonNode corrected = location(document(802, admin()), 9423);
    assertThat(corrected.get("location").asText()).isEqualTo("Second Fix");
    assertThat(corrected.at("/originalValues/location/value").asText()).isEqualTo("Submitted Name");
    assertThat(corrected.at("/originalValues/netArea/value").asText()).isEqualTo("18");
    assertThat(corrected.at("/originalValues/actualCost/value").asText())
        .as("the snapshot of detail 5833 itself, not the older 5899 row with the higher audit id")
        .isEqualTo("900");

    // A location the ministry ADDED at S has no snapshot: every tracked field is on file as empty.
    JsonNode added = null;
    for (JsonNode loc : document(802, admin()).get("locations")) {
      if ("Ministry Added".equals(loc.get("location").asText())) {
        added = loc;
      }
    }
    assertThat(added).isNotNull();
    for (String key :
        List.of("location", "biogeoclimaticCatalogueId", "netArea", "actualCost", "plannedCost")) {
      assertThat(added.at("/originalValues/" + key + "/value").asText()).as(key).isEmpty();
      assertThat(added.at("/originalValues/" + key + "/tooltip").asText())
          .isEqualTo("Original Submission Value: ");
    }
  }

  @Test
  @DisplayName("AC 2: a stale revisionCount on any row -> 409, and nothing is written")
  void staleRevision_409_writesNothing() throws Exception {
    String before = footprint(805);

    mockMvc
        .perform(
            save(805, saveBody(item(9428, fields("Stale", 8801, "10", "300", 0)), ""))
                .with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(STALE)));

    assertThat(footprint(805)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC 2: an unknown id, to update or to delete, -> 404, and nothing is written")
  void unknownId_404_writesNothing() throws Exception {
    String before = footprint(805);

    mockMvc
        .perform(
            save(805, saveBody(item(999999, fields("X", 8801, "1", "1", 0)), "")).with(admin()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail", is(NOT_FOUND)));
    // A delete of a real row in the SAME request is rolled back with the refusal.
    mockMvc
        .perform(save(805, saveBody("", "9428,999999")).with(admin()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail", is(NOT_FOUND)));

    assertThat(footprint(805)).isEqualTo(before);
  }

  static List<Object[]> refusals() {
    return refusalsFor(9427);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("refusals")
  @DisplayName(
      "AC 6: every refusal the Licensee gets holds for the admin at S — verbatim, nothing written")
  void refusalTable_asAdminAtSubmitted(String label, String items, String detail) throws Exception {
    String before = footprint(804);

    mockMvc
        .perform(save(804, saveBody(items, "")).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", containsString(detail)));

    assertThat(footprint(804)).as(label).isEqualTo(before);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("addRefusals")
  @DisplayName("AC 6: the same field refusals hold on Add for the admin at S — nothing written")
  void addRefusalTable_asAdminAtSubmitted(String label, String location, String detail)
      throws Exception {
    String before = footprint(804);

    mockMvc
        .perform(
            post(LOCATIONS)
                .with(csrf())
                .param("millId", "804")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(location)
                .with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", containsString(detail)));

    assertThat(footprint(804)).as(label).isEqualTo(before);
  }

  static List<Object[]> malformedBodies() {
    return malformedBodiesFor(9427);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("malformedBodies")
  @DisplayName("AC 2: a malformed save body is a 400 naming the missing value, never a 500")
  void malformedBody_400_writesNothing(String label, String body) throws Exception {
    String before = footprint(804);

    mockMvc
        .perform(save(804, body).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", containsString("Value Required")));

    assertThat(footprint(804)).as(label).isEqualTo(before);
  }

  @Test
  @DisplayName(
      "AC 2: another mill's location id, to update or to delete, is a 404 — neither mill written")
  void otherMillsId_404_writesNeitherMill() throws Exception {
    String ownerBefore = footprint(804);
    String callerBefore = footprint(805);

    // 9427 is 804's row; the request is made against 805.
    mockMvc
        .perform(save(805, saveBody("", "9427")).with(admin()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail", is(NOT_FOUND)));
    mockMvc
        .perform(
            save(805, saveBody(item(9427, fields("Taken", 8801, "9", "100", 0)), "")).with(admin()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail", is(NOT_FOUND)));

    assertThat(footprint(804)).as("the owner's rows").isEqualTo(ownerBefore);
    assertThat(footprint(805)).as("the caller's rows").isEqualTo(callerBefore);
  }

  @Test
  @DisplayName("AC 8: the admin at a NULL silviculture status (\"Not Initiated\") is refused 409")
  void adminAtNullStatus_refused() throws Exception {
    // 514/2021 has a status row with no silviculture code (V2; read elsewhere, never written here —
    // the gate refuses before the unknown id is ever looked up).
    mockMvc
        .perform(save(514, saveBody("", "999999")).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(NOT_EDITABLE)));
  }

  @Test
  @DisplayName("AC 6 (CHK-011 S17): several invalid fields in one save are all reported at once")
  void multiErrorBatch_reportsEveryFailure() throws Exception {
    String bad = item(9427, fields("", 8801, "1000000", "100000000", 0));

    mockMvc
        .perform(save(804, saveBody(bad, "")).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail", containsString("Location: Value is required.")))
        .andExpect(jsonPath("$.detail", containsString("Entered NAR (ha) must be between")))
        .andExpect(jsonPath("$.detail", containsString("Entered cost must be between")));
  }

  @Test
  @DisplayName("AC 2: a save that would duplicate the biogeo/location key -> 409, nothing written")
  void uniqueKeyClash_409_writesNothing() throws Exception {
    String before = footprint(803);

    // 9426 takes 9425's (BEC 8801, 'Missing Planned') key.
    mockMvc
        .perform(
            save(
                    803,
                    saveBody(
                        item(9426, fields("Missing Planned", 8801, "8", "800", revision(9426))),
                        ""))
                .with(admin()))
        .andExpect(status().isConflict())
        .andExpect(
            jsonPath(
                "$.detail",
                is(
                    "Schedule could not be saved. The Biogeo/Subzone/Variant has to be unique for a"
                        + " location.")));

    assertThat(footprint(803)).isEqualTo(before);
  }

  @Test
  @DisplayName(
      "AC 5: Check Status at Submitted flags the missing cost verbatim and mutates nothing")
  void checkStatusAtSubmitted_mutatesNothing() throws Exception {
    String before = footprint(803);

    mockMvc
        .perform(
            post(CHECK_STATUS)
                .with(csrf())
                .param("millId", "803")
                .param("year", "2021")
                .with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.requirementsMet", is(false)))
        .andExpect(
            jsonPath(
                "$.errors[*].text",
                hasItem("location  : Missing Planned - Planned cost: Value Required")));

    assertThat(footprint(803)).isEqualTo(before);
  }

  @Test
  @DisplayName(
      "AC 8: the admin at silviculture D is refused on Add and on the save; read-only page")
  void adminAtDraft_refused() throws Exception {
    String before = footprint(806);

    assertThat(document(806, admin()).get("editable").asBoolean()).isFalse();
    mockMvc
        .perform(
            save(806, saveBody(item(9429, fields("No", 8801, "11", "500", 0)), "")).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(NOT_EDITABLE)));
    mockMvc
        .perform(
            post(LOCATIONS)
                .with(csrf())
                .param("millId", "806")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"location\":\"No\",\"enhancedIndicator\":false,"
                        + "\"biogeoclimaticCatalogueId\":8801,\"netArea\":1}")
                .with(admin()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(NOT_EDITABLE)));

    assertThat(footprint(806)).isEqualTo(before);
  }

  @Test
  @DisplayName(
      "AC 9: the Licensee at silviculture D saves an edit on the rebuilt page; at S, refused")
  void licensee_savesAtDraft_andIsRefusedAtSubmitted() throws Exception {
    int rev = revision(9429);
    mockMvc
        .perform(
            save(806, saveBody(item(9429, fields("Licensee Fix", 8801, "12", "550", rev)), ""))
                .with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message.text", is(SAVED)))
        .andExpect(
            jsonPath("$.locations[?(@.locationId==9429)].location", hasItem("Licensee Fix")));

    String before = footprint(804);
    mockMvc
        .perform(
            save(804, saveBody(item(9427, fields("No", 8801, "9", "100", 0)), ""))
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.detail", is(NOT_EDITABLE)));
    assertThat(footprint(804)).isEqualTo(before);
  }

  @Test
  @DisplayName("AC 8: the save's context guards — 400 no mill, 409 closed mill, 404 no status row")
  void contextGuards_onTheSave() throws Exception {
    String body = saveBody("", "9427");
    mockMvc
        .perform(
            put(LOCATIONS)
                .with(csrf())
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.detail", is("Please Select Mill and Reporting Year in the Home Page. ")));
    mockMvc
        .perform(save(516, body).with(admin()))
        .andExpect(status().isConflict())
        .andExpect(
            jsonPath(
                "$.detail",
                is(
                    "This Mill is not active for the current Reporting Year. Please select another"
                        + " mill from the Home Page.")));
    mockMvc
        .perform(
            put(LOCATIONS)
                .with(csrf())
                .param("millId", "804")
                .param("year", "1999")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .with(admin()))
        .andExpect(status().isNotFound());
  }
}
