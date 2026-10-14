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
 * Acceptance test for authorization on GENERATE_MILL_REPORTS (AD-7). Security ON; drives the real
 * {@code oauth2ResourceServer} chain + {@code @PreAuthorize}.
 *
 * <p>Both production roles pass the gate: since #468 a SUBMITTER holds GENERATE_MILL_REPORTS too,
 * because legacy showed a Licensee the Generate Reports menu and let them open the mill reports —
 * scoped, as legacy's were, to their associated mills. So the submitter arms differ by IDENTITY: a
 * JWT with no directory GUID is refused (403 — no identity is not "no mills"), a GUID no xref row
 * associates passes the gate and meets the no-mills 404 (nothing in scope), and the canonical
 * submitter (associated to every seeded mill) streams the PDF. The no-groups arm is what separates
 * this gate from an absent one.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/reports/mill-information — authorization on GENERATE_MILL_REPORTS (AD-7)")
class MillInformationReportAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/reports/mill-information";
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
        .perform(get(ENDPOINT).param("year", SEEDED_YEAR).accept(MediaType.APPLICATION_PDF))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER whose JWT carries no directory GUID -> 403: no identity to scope by")
  void submitterWithoutIdentity_returns403() throws Exception {
    // A missing custom:idp_user_id is a claim-mapping problem and surfaces as an audited 403,
    // never as a plausible "no mills" 404 (#468 review).
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_PDF)
                .with(jwtWithGroups(List.of("ILCR_SUBMITTER"))))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName(
      "unassociated ILCR_SUBMITTER -> past the gate, then 404: no mills in their scope (#468)")
  void unassociatedSubmitter_returns404NoMills() throws Exception {
    // A real identity that no xref row associates to any mill: nothing in scope, so the render has
    // nothing to cover — the same no-mills 404 an empty year yields, and never everyone's report.
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_PDF)
                .with(unassociatedSubmitter()))
        .andExpect(status().isNotFound());
  }

  @Test
  @DisplayName(
      "the canonical submitter, associated to every seeded mill -> 200 and the PDF streams (#468)")
  void associatedSubmitter_returnsPdf() throws Exception {
    streamPdf(
            get(ENDPOINT)
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
            get(ENDPOINT)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_PDF)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("ILCR_ADMIN -> 200 and the PDF streams")
  void admin_returnsPdf() throws Exception {
    streamPdf(
            get(ENDPOINT)
                .param("year", SEEDED_YEAR)
                .accept(MediaType.APPLICATION_PDF)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isOk());
  }
}
