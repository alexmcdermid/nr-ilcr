package ca.bc.gov.nrs.ilcr.millreportstatus;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
 * Acceptance test for authorization on GENERATE_MILL_REPORTS (AD-7). Security ON; drives the real
 * {@code oauth2ResourceServer} chain + {@code @PreAuthorize}.
 *
 * <p>A 1:1 clone of {@code MillInformationReportAuthorizationIT}'s gate against this story's JSON
 * endpoint. Both production roles pass the gate: since #468 a SUBMITTER holds GENERATE_MILL_REPORTS
 * too, because legacy showed a Licensee the Generate Reports menu and let them open the mill
 * reports — scoped, as legacy's were ({@code MillReportStatusDAO.java:173}), to the mills they are
 * associated to. So the submitter arms differ by IDENTITY: a submitter whose JWT carries no
 * directory GUID is refused (403 — no identity is not "no mills"), one with a GUID no xref row
 * associates is served an EMPTY table, and the canonical one (associated to every seeded mill) the
 * full one. The no-groups arm is what separates this gate from an absent one.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/reports/mill-status — authorization on GENERATE_MILL_REPORTS (AD-7)")
class MillReportStatusAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/reports/mill-status";
  private static final String SEEDED_YEAR = "2021";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  /** A submitter with a real directory GUID that no seeded xref row associates to any mill. */
  private RequestPostProcessor unassociatedSubmitter() {
    return jwt()
        .jwt(
            j ->
                j.claim("idir_user_guid", "UNASSOCIATEDSUBMITTERXXXX0000001")
                    .claim("identity_provider", "azureidir")
                    .claim("client_roles", List.of("ILCR_SUBMITTER")))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no token (anonymous) -> 401")
  void anonymous_returns401() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).param("year", SEEDED_YEAR).accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER whose JWT carries no directory GUID -> 403: no identity to scope by")
  void submitterWithoutIdentity_returns403() throws Exception {
    // Past the gate (the role holds the action), then refused: a missing custom:idp_user_id is a
    // claim-mapping problem, and it must surface as an audited 403 — not masquerade as a user who
    // happens to have no mills (#468 review).
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_JSON)
                .with(jwtWithGroups(List.of("ILCR_SUBMITTER"))))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("unassociated ILCR_SUBMITTER -> 200 with an EMPTY table: their mills, none (#468)")
  void unassociatedSubmitter_returnsEmptyTable() throws Exception {
    // A real identity that no xref row associates to any mill: genuinely nothing to show, and
    // "nothing" must never read as "everything".
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_JSON)
                .with(unassociatedSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$").isArray())
        .andExpect(jsonPath("$", hasSize(0)));
  }

  @Test
  @DisplayName(
      "the canonical submitter, associated to every seeded mill, is served the rows (#468)")
  void associatedSubmitter_returnsRows() throws Exception {
    // Mill association is the whole point here (#468): the table is scoped to the caller's mills,
    // as legacy's Restrictions.in made it, and this caller is associated to all of them.
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_JSON)
                .with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$").isArray())
        .andExpect(jsonPath("$", not(empty())));
  }

  @Test
  @DisplayName("no groups at all -> 403")
  void noGroups_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_JSON)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("ILCR_ADMIN -> 200 and the rows are served")
  void admin_returnsRows() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_JSON)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isOk())
        // An ARRAY, not a row count. The fixture count is MillReportStatusIT's to own; asserting it
        // here would make any new 2021 fixture fail two tests for one reason, with the second
        // failure pointing at the security chain.
        .andExpect(jsonPath("$").isArray());
  }
}
