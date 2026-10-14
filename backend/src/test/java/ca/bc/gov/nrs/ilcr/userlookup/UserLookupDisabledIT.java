package ca.bc.gov.nrs.ilcr.userlookup;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.assignment.MillAssociationService;
import ca.bc.gov.nrs.ilcr.assignment.dto.MillSubmitter;
import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * Acceptance test for the state the slice actually ships in: {@code ilcr.user-lookup.enabled} off,
 * which is the default in every environment until the DL-27 service account exists.
 *
 * <p>This is the flag's whole safety story, and without a test nothing observes it — dropping the
 * {@code @ConditionalOnProperty} from the controller would put the endpoint live everywhere with
 * blank credentials, and every other test in this package would stay green because they all force
 * the flag on.
 *
 * <p>Sibling of {@link UserLookupIT}, which covers the enabled path.
 */
@TestPropertySource(properties = {"ilcr.security.enabled=true", "ilcr.user-lookup.enabled=false"})
@DisplayName("GET /api/v1/users/lookup — absent while the feature flag is off (Story 2.3)")
class UserLookupDisabledIT extends AbstractOracleIT {

  /**
   * ACT carrying one seeded ACTIVE assignment, the deactivation-blocked fixture (R__75). Its
   * canonical-submitter assignment is inserted there explicitly, not inherited from R__70, because
   * R__70's set-based insert runs before this mill's status-xref row exists
   * (R__75_mill_maintenance_ fixtures.sql's own header note) — mill 751, the OTHER "ACTIVE" mill in
   * that file, is for exactly that reason seeded with no assignment at all.
   */
  private static final long ACTIVE_MILL = 752L;

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  @Autowired private MillAssociationService millAssociationService;

  @Test
  @DisplayName("the endpoint is not routed at all, even for an admin")
  void endpointIsAbsentForAdmin() throws Exception {
    mockMvc
        .perform(
            get("/api/v1/users/lookup")
                .param("firstName", "jane")
                .with(
                    jwt()
                        .jwt(
                            j ->
                                j.claim("identity_provider", "azureidir")
                                    .claim("client_roles", List.of("ILCR_ADMIN")))
                        .authorities(j -> CONVERTER.convert(j).getAuthorities())))
        .andExpect(status().isNotFound());
  }

  @Test
  @DisplayName("the assignments view is unaffected by the directory being switched off")
  void assignmentsStillAnswer() throws Exception {
    // The local xref never consults the directory, so turning the lookup off must not narrow the
    // admin screen that the picker will eventually sit on.
    mockMvc
        .perform(
            get("/api/v1/mills/{millId}/submitters", 514L)
                .with(
                    jwt()
                        .jwt(
                            j ->
                                j.claim("identity_provider", "azureidir")
                                    .claim("client_roles", List.of("ILCR_ADMIN")))
                        .authorities(j -> CONVERTER.convert(j).getAuthorities())))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName(
      "the mill-record association panel is wired without the lookup client and serves rows bare")
  void millAssociationServiceServesRowsWithoutNames() {
    // MillAssociationService's own gate (ilcr.datasource.enabled) is independent of
    // ilcr.user-lookup.enabled, so this context is exactly the shape that breaks if the
    // UserLookupClient were ever injected as a plain constructor parameter instead of an
    // ObjectProvider: the bean would fail to wire and every IT would fail identically, as all 1240
    // did in Story 21.2. Proving the bean resolves here, and that it still answers with names
    // absent, is the whole safety story for that trap.
    List<MillSubmitter> associations = millAssociationService.listByMill(ACTIVE_MILL, true);

    assertThat(associations).isNotEmpty();
    assertThat(associations).allSatisfy(row -> assertThat(row.firstName()).isNull());
  }
}
