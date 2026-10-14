package ca.bc.gov.nrs.ilcr.schedule5;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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
 * Story 7.4 acceptance — authorization on the sub-page endpoints (AC15; AD-7). Security ON, driving
 * the real {@code oauth2ResourceServer} chain and {@code @PreAuthorize}: {@code VIEW_SCHEDULE} on
 * the two GETs, {@code EDIT_SCHEDULE} on the four writes. Authorities come from the PRODUCTION
 * {@link FamJwtAuthenticationConverter}, so a change to the group-to-authority mapping fails here
 * rather than silently widening access.
 *
 * <p><strong>The 403 bodies are VALID on purpose.</strong> {@code @Valid} body binding runs during
 * argument resolution, BEFORE {@code @PreAuthorize} fires, so an invalid body would yield 400 and
 * the test would pass for the wrong reason — proving nothing about authorization.
 *
 * <p><strong>Mill 693 is this class's own fixture and its track is deliberately {@code
 * 'S'}</strong> — see the seed migration's block comment. Authorized writes therefore land on 409
 * from the Draft gate, which proves {@code @PreAuthorize} admitted them without this suite mutating
 * anything.
 *
 * <p><strong>Coverage gap (inherited, recorded on 25.2):</strong> a "holds VIEW but not EDIT → 403"
 * case is unreachable today because both shipped roles hold {@code EDIT_SCHEDULE}. It becomes
 * testable when the FAM auth story (DL-6) introduces a narrower view-only role.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Schedule 5 sub-pages — authorization on VIEW_SCHEDULE / EDIT_SCHEDULE (AC15)")
class Schedule5SubPageAuthorizationIT extends AbstractOracleIT {

  private static final String CAMP_ROWS = "/api/v1/schedule5/camps/8713/other-camp-expenses";
  private static final String ACCESS_ROWS = "/api/v1/schedule5/camps/8713/other-access-expenses";
  private static final String MILL = "693";
  private static final String YEAR = "2016";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  /** A VALID body — so a 403 fires at {@code @PreAuthorize}, not at {@code @Valid}. */
  private static final String VALID_BODY =
      """
      {"rows":[{"rowId":null,"description":"Authz Row","cost":10}]}
      """;

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private RequestPostProcessor submitter() {
    return canonicalSubmitter();
  }

  private RequestPostProcessor noGroup() {
    return jwtWithGroups(List.of());
  }

  // -----------------------------------------------------------------------------------------
  // Unauthenticated — 401 on every verb
  // -----------------------------------------------------------------------------------------

  @Test
  @DisplayName("no token -> 401 on every sub-page verb")
  void anonymousIsUnauthorized() throws Exception {
    mockMvc
        .perform(get(CAMP_ROWS).param("millId", MILL).param("year", YEAR))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(get(ACCESS_ROWS).param("millId", MILL).param("year", YEAR))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(
            put(CAMP_ROWS)
                .with(csrf())
                .param("millId", MILL)
                .param("year", YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(
            put(ACCESS_ROWS)
                .with(csrf())
                .param("millId", MILL)
                .param("year", YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(delete(CAMP_ROWS + "/8749").with(csrf()).param("millId", MILL).param("year", YEAR))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(
            delete(ACCESS_ROWS + "/8749").with(csrf()).param("millId", MILL).param("year", YEAR))
        .andExpect(status().isUnauthorized());
  }

  // -----------------------------------------------------------------------------------------
  // Authenticated but ungrouped — 403 on every verb
  // -----------------------------------------------------------------------------------------

  @Test
  @DisplayName("a token with no group -> 403 on both GETs (VIEW_SCHEDULE)")
  void noGroupCannotRead() throws Exception {
    mockMvc
        .perform(get(CAMP_ROWS).with(noGroup()).param("millId", MILL).param("year", YEAR))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(get(ACCESS_ROWS).with(noGroup()).param("millId", MILL).param("year", YEAR))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("a token with no group -> 403 on both PUTs (EDIT_SCHEDULE)")
  void noGroupCannotSave() throws Exception {
    mockMvc
        .perform(
            put(CAMP_ROWS)
                .with(noGroup())
                .with(csrf())
                .param("millId", MILL)
                .param("year", YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            put(ACCESS_ROWS)
                .with(noGroup())
                .with(csrf())
                .param("millId", MILL)
                .param("year", YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("a token with no group -> 403 on both DELETEs (EDIT_SCHEDULE)")
  void noGroupCannotDelete() throws Exception {
    mockMvc
        .perform(
            delete(CAMP_ROWS + "/8749")
                .with(noGroup())
                .with(csrf())
                .param("millId", MILL)
                .param("year", YEAR))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            delete(ACCESS_ROWS + "/8749")
                .with(noGroup())
                .with(csrf())
                .param("millId", MILL)
                .param("year", YEAR))
        .andExpect(status().isForbidden());
  }

  // -----------------------------------------------------------------------------------------
  // Authorized — admitted by @PreAuthorize, then stopped by the Draft gate
  // -----------------------------------------------------------------------------------------

  @Test
  @DisplayName("ILCR_SUBMITTER may READ — 200, and the row is served read-only")
  void submitterMayRead() throws Exception {
    mockMvc
        .perform(get(CAMP_ROWS).with(submitter()).param("millId", MILL).param("year", YEAR))
        .andExpect(status().isOk());
    mockMvc
        .perform(get(ACCESS_ROWS).with(submitter()).param("millId", MILL).param("year", YEAR))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER is ADMITTED to the writes — 409 from the Draft gate, not 403")
  void submitterIsAdmittedToWrites() throws Exception {
    // 409, not 403: authorization passed and the non-Draft track stopped the write. Nothing is
    // mutated either way, which is what lets this class own its fixture safely.
    mockMvc
        .perform(
            put(CAMP_ROWS)
                .with(submitter())
                .with(csrf())
                .param("millId", MILL)
                .param("year", YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isConflict());
    mockMvc
        .perform(
            put(ACCESS_ROWS)
                .with(submitter())
                .with(csrf())
                .param("millId", MILL)
                .param("year", YEAR)
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY))
        .andExpect(status().isConflict());
    mockMvc
        .perform(
            delete(CAMP_ROWS + "/8749")
                .with(submitter())
                .with(csrf())
                .param("millId", MILL)
                .param("year", YEAR))
        .andExpect(status().isConflict());
    mockMvc
        .perform(
            delete(ACCESS_ROWS + "/8749")
                .with(submitter())
                .with(csrf())
                .param("millId", MILL)
                .param("year", YEAR))
        .andExpect(status().isConflict());
  }
}
