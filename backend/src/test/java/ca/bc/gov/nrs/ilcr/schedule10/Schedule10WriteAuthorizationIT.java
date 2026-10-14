package ca.bc.gov.nrs.ilcr.schedule10;

import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
 * Acceptance test — authorization on the Schedule 10 WRITE endpoints. Security ON, so this drives
 * the real resource-server chain and {@code @PreAuthorize}.
 *
 * <p>Every write names {@code EDIT_SCHEDULE}; Check Status names only {@code VIEW_SCHEDULE}, so a
 * caller who may read may also check readiness on a schedule they cannot edit.
 *
 * <p>Note both shipped groups hold both actions, so no reachable principal can separate them here.
 * These tests pin the "no group at all" and "foreign group" cases.
 *
 * <p><strong>What is NOT pinned, stated plainly.</strong> An earlier version of this note claimed
 * "the unit-level controller test pins that the write path asks for the EDIT action by name". No
 * such test exists — {@code Schedule10ControllerTest} covers only {@code getSchedule10}, and none
 * of the eight write handlers is unit-tested. Because both production groups hold both actions,
 * changing {@code mayEdit()} to ask for {@code VIEW_SCHEDULE} would pass this entire suite.
 * Recorded at code review 2026-08-18 rather than left as a claim the tests do not support; closing
 * it needs either a principal that holds one action and not the other, or a controller-level unit
 * test.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Schedule 10 — authorization on the write endpoints")
class Schedule10WriteAuthorizationIT extends AbstractOracleIT {

  private static final String PAGES = "/api/v1/schedule10/pages";
  private static final String CHECK_STATUS = "/api/v1/schedule10/check-status";

  /**
   * The Check Status body with no editor open (#359) — so the POST reaches authorization, not 400.
   */
  private static final String NO_EDITOR = "{\"page\":null,\"road\":null}";

  private static final String MILL = "717";
  private static final String YEAR = "2024";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  private static final String PAGE_BODY =
      """
      {"forestRegionCode":"RNI","tsaOrTfl":"01","supplyBlock":"01A","divisionName":"Authz",
       "constructionPeriod":"2021-06","revisionCount":0}
      """;

  private static final String DETAIL_BODY =
      """
      {"roadName":"Authz Road","roadLifetimeCode":"P","becbiogeoCatalogueId":8801,
       "relSoilMoistRgmClsCode":"1","stabilizing":{"ballastMethodCode":"N"},"revisionCount":0}
      """;

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no group -> 403 on every write endpoint")
  void noPermissionIsForbiddenOnEveryWrite() throws Exception {
    RequestPostProcessor none = jwtWithGroups(List.of());

    mockMvc
        .perform(
            post(PAGES)
                .param("millId", MILL)
                .param("year", YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(PAGE_BODY)
                .with(csrf())
                .with(none))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));

    mockMvc
        .perform(
            put(PAGES + "/8956")
                .param("millId", MILL)
                .param("year", "2019")
                .contentType(MediaType.APPLICATION_JSON)
                .content(PAGE_BODY)
                .with(csrf())
                .with(none))
        .andExpect(status().isForbidden());

    mockMvc
        .perform(
            post(PAGES + "/8956/copy")
                .param("millId", MILL)
                .param("year", "2019")
                .with(csrf())
                .with(none))
        .andExpect(status().isForbidden());

    mockMvc
        .perform(
            delete(PAGES + "/8956")
                .param("millId", MILL)
                .param("year", "2019")
                .with(csrf())
                .with(none))
        .andExpect(status().isForbidden());

    // A VALID body on purpose. Spring resolves and validates @RequestBody arguments before it
    // invokes the method, so @PreAuthorize has not run yet — an invalid body would answer 400 and
    // this test would prove nothing about authorization.
    mockMvc
        .perform(
            post(PAGES + "/8956/road-details")
                .param("millId", MILL)
                .param("year", "2019")
                .contentType(MediaType.APPLICATION_JSON)
                .content(DETAIL_BODY)
                .with(csrf())
                .with(none))
        .andExpect(status().isForbidden());

    mockMvc
        .perform(
            put(PAGES + "/8956/road-details/8969")
                .param("millId", MILL)
                .param("year", "2019")
                .contentType(MediaType.APPLICATION_JSON)
                .content(DETAIL_BODY)
                .with(csrf())
                .with(none))
        .andExpect(status().isForbidden());

    mockMvc
        .perform(
            delete(PAGES + "/8956/road-details/8969")
                .param("millId", MILL)
                .param("year", "2019")
                .with(csrf())
                .with(none))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("a foreign group -> 403")
  void foreignGroupIsForbidden() throws Exception {
    mockMvc
        .perform(
            post(PAGES)
                .param("millId", MILL)
                .param("year", YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(PAGE_BODY)
                .with(csrf())
                .with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("Check Status is refused without VIEW_SCHEDULE and allowed with it")
  void checkStatusRequiresViewOnly() throws Exception {
    mockMvc
        .perform(
            post(CHECK_STATUS)
                .param("millId", "719")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(NO_EDITOR)
                .with(csrf())
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());

    mockMvc
        .perform(
            post(CHECK_STATUS)
                .param("millId", "719")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(NO_EDITOR)
                .with(csrf())
                .with(canonicalSubmitter()))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("a submitter reaches the Draft gate rather than being refused authorization")
  void submitterPassesAuthorizationAndMeetsTheDraftGate() throws Exception {
    // Mill 718 sits on track 'S'. A 409 here proves authorization passed and the status gate is
    // what
    // refused the write — a 403 would mean the two were conflated.
    mockMvc
        .perform(
            post(PAGES)
                .param("millId", "718")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(PAGE_BODY)
                .with(csrf())
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }

  // -----------------------------------------------------------------------------------------
  // The ADMIN row of the role×status matrix (Story 16.1; added on the #427 review). Mill 746/2021
  // is 1–10 'V' and silviculture 'D' (R__51) — so a gate that read the wrong track's column would
  // see Draft, refuse the administrator, and every test below would fail on a 409 instead of
  // passing vacuously. The shared unit truth table proves the component; these prove THIS
  // schedule's wiring to it, on the write verb AND on DELETE.
  // -----------------------------------------------------------------------------------------

  @Test
  @DisplayName("ILCR_ADMIN WRITES at a VERIFIED track -> 2xx, and the track stays 'V' (AD-9)")
  void admin_writesAtVerified() throws Exception {
    mockMvc
        .perform(
            post(PAGES)
                .param("millId", "746")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(PAGE_BODY)
                .with(csrf())
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        // The correction must not move the track, and the echo must report the status the gate
        // actually read — not a STATUS_DRAFT literal passed in its place.
        .andExpect(jsonPath("$.trackStatus", is("V")))
        .andExpect(jsonPath("$.editable", is(true)));
  }

  @Test
  @DisplayName("ILCR_ADMIN DELETES a page at a VERIFIED track -> 2xx (the correction path)")
  void admin_deletesAtVerified() throws Exception {
    // Page 8990 is R__51's seeded delete target on this mill and carries no road details, so this
    // removes a real row. Schedule 10 is also the one service whose gate literal was locally named
    // DRAFT rather than STATUS_DRAFT, which is exactly the kind of copy that gets missed in a
    // sweep — and a refused-at-Draft probe cannot tell a missed one from a converted one.
    mockMvc
        .perform(
            delete(PAGES + "/8990")
                .param("millId", "746")
                .param("year", "2021")
                .with(csrf())
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful())
        .andExpect(jsonPath("$.trackStatus", is("V")));
  }

  @Test
  @DisplayName("A SUBMITTER at that same VERIFIED track -> 409: only the ministry corrects")
  void submitter_refusedAtVerified() throws Exception {
    // The other half of the row. Without it, admin_writesAtVerified alone would also pass if the
    // gate had simply been widened to "anyone may edit at V".
    mockMvc
        .perform(
            post(PAGES)
                .param("millId", "746")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(PAGE_BODY)
                .with(csrf())
                .with(canonicalSubmitter()))
        .andExpect(status().isConflict());
  }
}
