package ca.bc.gov.nrs.ilcr.reporting;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
 * Acceptance test for authorization on the per-mill drill-down (AD-7). Security ON; drives the real
 * {@code oauth2ResourceServer} chain + {@code @PreAuthorize} against real JWTs.
 *
 * <p>The drill-down reuses {@code GENERATE_MILL_REPORTS} rather than introducing an action of its
 * own: it is the Mill Information report scoped to one mill, so it is the same permission over the
 * same content. This suite exists because the gate has to be proven on the NEW endpoint — a
 * {@code @PreAuthorize} omitted from one controller method is invisible to every other test here,
 * and this one carries client names, phone numbers and addresses.
 *
 * <p>As on the all-mills endpoint, both production roles pass the gate since #468 (legacy let a
 * Licensee open the mill reports), and the drill-down is then narrowed to a submitter's associated
 * mills — one row of the scoped status table it is launched from. So a submitter with no directory
 * GUID is 403 (no identity to scope by), an unassociated one is 403 on a real mill AND on an
 * unknown one (denied before the read, learning nothing), while the canonical submitter streams the
 * PDF. The no-groups arm proves the gate is there at all.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName(
    "GET /api/v1/reports/mill-information/{millId} — authorization on GENERATE_MILL_REPORTS (AD-7)")
class MillDrillDownAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/reports/mill-information/{millId}";
  private static final long SEEDED_MILL = 730;
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
        .perform(
            get(ENDPOINT, SEEDED_MILL).param("year", SEEDED_YEAR).accept(MediaType.APPLICATION_PDF))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER whose JWT carries no directory GUID -> 403: no identity to scope by")
  void submitterWithoutIdentity_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT, SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_PDF)
                .with(jwtWithGroups(List.of("ILCR_SUBMITTER"))))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("unassociated ILCR_SUBMITTER -> 403: the mill is not in their scope (#468)")
  void unassociatedSubmitter_returns403() throws Exception {
    // A real identity that no xref row associates to this mill: the scope check refuses before the
    // read.
    mockMvc
        .perform(
            get(ENDPOINT, SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_PDF)
                .with(unassociatedSubmitter()))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName(
      "the canonical submitter, associated to every seeded mill -> 200 and the PDF streams (#468)")
  void associatedSubmitter_returnsPdf() throws Exception {
    streamPdf(
            get(ENDPOINT, SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_PDF)
                .with(canonicalSubmitter()))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("no groups at all -> 403")
  void noGroups_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT, SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_PDF)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("ILCR_ADMIN -> 200 and the PDF streams")
  void admin_returnsPdf() throws Exception {
    streamPdf(
            get(ENDPOINT, SEEDED_MILL)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_PDF)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName(
      "an unassociated SUBMITTER is denied before the mill is ever read — 403, not the 404")
  void unassociatedSubmitterIsDeniedEvenForAnUnknownMill() throws Exception {
    // The scope check precedes the read, so a submitter learns nothing about which mills exist: a
    // real mill outside their scope and a mill that does not exist answer identically. Were the
    // order reversed, the 404/403 split would leak the year's mill set.
    mockMvc
        .perform(
            get(ENDPOINT, 999_999)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_PDF)
                .with(unassociatedSubmitter()))
        .andExpect(status().isForbidden());
  }
}
