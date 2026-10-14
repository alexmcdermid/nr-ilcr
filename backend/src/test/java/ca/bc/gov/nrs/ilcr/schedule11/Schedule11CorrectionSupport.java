package ca.bc.gov.nrs.ilcr.schedule11;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Shared ground for the ministry-correction acceptance tests — at Submitted ({@link
 * Schedule11CorrectionIT}) and at Verified ({@link Schedule11LateCorrectionIT}). Both prove the
 * same thing at a different status: rows written, no track moved, no audit row written. So the
 * database reads that prove it, the request shapes and the refusal tables live here once, and a
 * rule tightened for one status cannot silently drift from the other.
 *
 * <p>Security ON in both subclasses: the admin's authorities come through the production {@link
 * FamJwtAuthenticationConverter}. The test post-processor names the token from its {@code sub}
 * rather than the converter's {@code custom:idp_username}, so both carry the one audit name the
 * write must stamp.
 */
abstract class Schedule11CorrectionSupport extends AbstractOracleIT {

  static final String ENDPOINT = "/api/v1/schedule11";
  static final String LOCATIONS = ENDPOINT + "/locations";
  static final String CHECK_STATUS = ENDPOINT + "/check-status";
  static final String ADMIN_NAME = "IDIR\\CORRECTOR";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  static final String SAVED = "Data saved successfully";
  static final String STALE =
      "This schedule was changed by another user. Please reload and try again.";
  static final String NOT_EDITABLE = "This schedule cannot be edited in its current status.";
  static final String NOT_FOUND = "Location not found.";

  /** The five fields that carry an original-value indicator (Enhanced and Comments never do). */
  static final List<String> TRACKED =
      List.of("location", "biogeoclimaticCatalogueId", "netArea", "actualCost", "plannedCost");

  @MockitoBean private JwtDecoder jwtDecoder;
  @Autowired JdbcTemplate jdbc;
  final ObjectMapper mapper = new ObjectMapper();

  static RequestPostProcessor admin() {
    return jwt()
        .jwt(
            j ->
                j.subject(ADMIN_NAME)
                    .claim("identity_provider", "azureidir")
                    .claim("client_roles", List.of("ILCR_ADMIN"))
                    .claim("idir_username", ADMIN_NAME)
                    .claim("idir_user_guid", "CORRECTORADMIN00000000000000001"))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  static MockHttpServletRequestBuilder save(long mill, String body) {
    return put(LOCATIONS)
        .with(csrf())
        .param("millId", String.valueOf(mill))
        .param("year", "2021")
        .contentType(MediaType.APPLICATION_JSON)
        .content(body);
  }

  static MockHttpServletRequestBuilder add(long mill, String body) {
    return post(LOCATIONS)
        .with(csrf())
        .param("millId", String.valueOf(mill))
        .param("year", "2021")
        .contentType(MediaType.APPLICATION_JSON)
        .content(body);
  }

  static String saveBody(String items, String deletedIds) {
    return "{\"locations\":[" + items + "],\"deletedIds\":[" + deletedIds + "]}";
  }

  static String item(long id, String location) {
    return "{\"basicSilvicultureReportId\":" + id + ",\"location\":" + location + "}";
  }

  static String fields(String location, long bec, String nar, String actual, int rev) {
    return """
        {"location":"%s","enhancedIndicator":false,"biogeoclimaticCatalogueId":%d,"netArea":%s,
         "actualCost":%s,"plannedCost":2000,"revisionCount":%d}
        """
        .formatted(location, bec, nar, actual, rev);
  }

  Map<String, Object> statusRow(long mill) {
    return jdbc.queryForMap(
        "SELECT ILCR_MILL_REPORT_STATUS_CODE, MILL_SILVICULTUR_STATUS_CODE, REVISION_COUNT,"
            + " UPDATE_USERID, UPDATE_TIMESTAMP, LICENSEE_USER_GUID, AUDITOR_USER_GUID"
            + " FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021",
        mill);
  }

  List<Map<String, Object>> categories(long mill) {
    return jdbc.queryForList(
        "SELECT ILCR_CATEGORY_ID, CATEGORY_STATE_CODE, REVISION_COUNT, UPDATE_USERID,"
            + " UPDATE_TIMESTAMP FROM THE.ILCR_REPORT_CATEGORY"
            + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021 ORDER BY TO_NUMBER(ILCR_CATEGORY_ID)",
        mill);
  }

  /** Every Schedule 11 location and cost row of the mill, and every audit row, as one string. */
  String footprint(long mill) {
    return jdbc.queryForList(
                "SELECT BASIC_SILVICULTURE_REPORT_ID, LOCATION, BECBIOGEOCLIMATIC_CATALOGUE_ID,"
                    + " REFORESTED_NET_AREA, ENHANCED_IND, COMMENTS, REVISION_COUNT, UPDATE_USERID,"
                    + " UPDATE_TIMESTAMP FROM THE.BASIC_SILVICULTURE_REPORT"
                    + " WHERE ILCR_MILL_ID = ? AND REPORT_YEAR = 2021"
                    + " ORDER BY BASIC_SILVICULTURE_REPORT_ID",
                mill)
            .toString()
        + jdbc.queryForList(
                "SELECT d.ILCR_COST_REPORT_DETAIL_ID, d.ILCR_REPORT_COST_ITEM_ID, d.COST,"
                    + " d.UPDATE_USERID, d.UPDATE_TIMESTAMP FROM THE.ILCR_COST_REPORT_DETAIL d"
                    + " JOIN THE.BASIC_SILVICULTURE_REPORT b"
                    + " ON b.BASIC_SILVICULTURE_REPORT_ID = d.BASIC_SILVICULTURE_REPORT_ID"
                    + " WHERE b.ILCR_MILL_ID = ? AND b.REPORT_YEAR = 2021"
                    + " ORDER BY d.ILCR_COST_REPORT_DETAIL_ID",
                mill)
            .toString()
        + statusRow(mill)
        + categories(mill);
  }

  /** Count and latest touch of both audit tables: the application must never write one. */
  String auditTables() {
    return jdbc.queryForObject(
            "SELECT COUNT(*) || '/' || NVL(TO_CHAR(MAX(UPDATE_TIMESTAMP), 'YYYYMMDDHH24MISS'),'-')"
                + " FROM THE.BASIC_SILVICULTURE_RPRT_AUD",
            String.class)
        + ";"
        + jdbc.queryForObject(
            "SELECT COUNT(*) || '/' || NVL(TO_CHAR(MAX(UPDATE_TIMESTAMP), 'YYYYMMDDHH24MISS'),'-')"
                + " FROM THE.ILCR_COST_REPORT_DETAIL_AUD",
            String.class);
  }

  int revision(long locationId) {
    return jdbc.queryForObject(
        "SELECT REVISION_COUNT FROM THE.BASIC_SILVICULTURE_REPORT"
            + " WHERE BASIC_SILVICULTURE_REPORT_ID = ?",
        Integer.class,
        locationId);
  }

  JsonNode document(long mill, RequestPostProcessor who) throws Exception {
    return mapper.readTree(
        mockMvc
            .perform(
                get(ENDPOINT)
                    .param("millId", String.valueOf(mill))
                    .param("year", "2021")
                    .accept(MediaType.APPLICATION_JSON)
                    .with(who))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString());
  }

  static JsonNode location(JsonNode document, long id) {
    for (JsonNode loc : document.get("locations")) {
      if (loc.get("locationId").asLong() == id) {
        return loc;
      }
    }
    throw new IllegalStateException("location " + id + " not served");
  }

  /**
   * The field rules, as the entered-fields JSON of a location (with {@code revisionCount} 0) and
   * the verbatim refusal. One source for both the bulk save and Add, so "on the bulk save and on
   * Add" cannot drift apart.
   */
  static List<Object[]> fieldRefusals() {
    String ok = fields("Refusal Block", 8801, "9", "100", 0);
    return List.<Object[]>of(
        new Object[] {
          "blank location", ok.replace("\"Refusal Block\"", "\"\""), "Location: Value is required."
        },
        new Object[] {
          "location over 30",
          ok.replace("Refusal Block", "x".repeat(31)),
          "Location must be 30 characters or fewer."
        },
        new Object[] {
          "missing enhanced",
          ok.replace("\"enhancedIndicator\":false,", ""),
          "Enhanced: Value is required."
        },
        new Object[] {
          "missing BEC",
          ok.replace("\"biogeoclimaticCatalogueId\":8801,", ""),
          "Biogeo/Subzone/Variant: Value is required."
        },
        new Object[] {
          "unresolvable BEC",
          fields("Refusal Block", 999999, "9", "100", 0),
          "Biogeo/Subzone/Variant code is invalid. The code must be corrected before the schedule"
              + " can be saved."
        },
        new Object[] {
          "missing NAR", ok.replace("\"netArea\":9,", ""), "NAR(ha): Value is required."
        },
        new Object[] {
          "NAR over range",
          fields("Refusal Block", 8801, "1000000", "100", 0),
          "Entered NAR (ha) must be between 0 and 999,999.9."
        },
        new Object[] {
          "NAR below range",
          fields("Refusal Block", 8801, "-1", "100", 0),
          "Entered NAR (ha) must be between 0 and 999,999.9."
        },
        new Object[] {
          "cost over range",
          fields("Refusal Block", 8801, "9", "100000000", 0),
          "Entered cost must be between -99,999,999 and 99,999,999."
        },
        new Object[] {
          "comments over 3500",
          ok.replace(
              "\"revisionCount\":0",
              "\"comments\":\"" + "c".repeat(3501) + "\",\"revisionCount\":0"),
          "Comments must be 3500 characters or fewer."
        });
  }

  /** The bulk-save refusal table, against the mill's {@code 'Refusal Block'} row {@code id}. */
  static List<Object[]> refusalsFor(long id) {
    String ok = fields("Refusal Block", 8801, "9", "100", 0);
    List<Object[]> rows = new ArrayList<>();
    for (Object[] field : fieldRefusals()) {
      rows.add(new Object[] {field[0], item(id, (String) field[1]), field[2]});
    }
    rows.add(
        new Object[] {
          "missing revisionCount",
          item(id, ok.replace(",\"revisionCount\":0", "")),
          "Revision count is required for an update."
        });
    rows.add(
        new Object[] {
          "the same location twice",
          item(id, ok) + "," + item(id, ok),
          "The same location was submitted more than once."
        });
    rows.add(new Object[] {"nothing to save", "", "There are no changes to save."});
    return rows;
  }

  static List<Object[]> addRefusals() {
    List<Object[]> rows = new ArrayList<>();
    for (Object[] field : fieldRefusals()) {
      // An Add carries no revisionCount: create has no token to echo.
      String location = ((String) field[1]).replace(",\"revisionCount\":0", "");
      rows.add(new Object[] {field[0], location, field[2]});
    }
    return rows;
  }

  static List<Object[]> malformedBodiesFor(long id) {
    String loc = fields("Refusal Block", 8801, "9", "100", 0);
    return List.<Object[]>of(
        new Object[] {"no locations list", "{\"deletedIds\":[]}"},
        new Object[] {"no deletedIds list", "{\"locations\":[]}"},
        new Object[] {"a null location item", "{\"locations\":[null],\"deletedIds\":[]}"},
        new Object[] {"a null deleted id", "{\"locations\":[],\"deletedIds\":[null]}"},
        new Object[] {
          "an item with no id", "{\"locations\":[{\"location\":" + loc + "}],\"deletedIds\":[]}"
        },
        new Object[] {
          "an item with no fields",
          "{\"locations\":[{\"basicSilvicultureReportId\":" + id + "}],\"deletedIds\":[]}"
        });
  }
}
