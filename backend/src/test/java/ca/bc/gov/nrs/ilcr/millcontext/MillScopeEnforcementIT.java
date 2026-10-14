package ca.bc.gov.nrs.ilcr.millcontext;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Story 5.7 — per-endpoint mill-scope enforcement. Proves the shared-guard check ({@code
 * MillContextService.validateMillAccess}) on a representative schedule endpoint and on {@code
 * mill-context}: a submitter NOT actively associated to the mill is 403'd (a forged/guessed {@code
 * millId}); the canonical associated submitter and an admin are not. Security ON.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Per-endpoint mill-scope enforcement (Story 5.7)")
class MillScopeEnforcementIT extends AbstractOracleIT {

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  private static final String SCHEDULE1 = "/api/v1/schedule1";
  private static final String MILL_CONTEXT = "/api/v1/mill-context";
  private static final String MILL = "514";
  private static final String YEAR = "2021";

  @MockitoBean private JwtDecoder jwtDecoder;

  /** A submitter with NO xref association to any mill (32-char GUID, never seeded). */
  private RequestPostProcessor unassociatedSubmitter() {
    return jwt()
        .jwt(j -> j.claim("idir_user_guid", "UNASSOCIATEDSUBMITTERXXXX0000001"))
        .authorities(new SimpleGrantedAuthority("SUBMITTER"));
  }

  private RequestPostProcessor admin() {
    return jwt()
        .jwt(
            j ->
                j.claim("identity_provider", "azureidir")
                    .claim("client_roles", List.of("ILCR_ADMIN")))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("submitter NOT associated to the mill — 403 on a schedule endpoint")
  void unassociatedSubmitter_forbiddenOnSchedule() throws Exception {
    mockMvc
        .perform(
            get(SCHEDULE1).param("millId", MILL).param("year", YEAR).with(unassociatedSubmitter()))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("submitter NOT associated to the mill — 403 on mill-context resolve")
  void unassociatedSubmitter_forbiddenOnMillContext() throws Exception {
    mockMvc
        .perform(
            get(MILL_CONTEXT)
                .param("millId", MILL)
                .param("year", YEAR)
                .with(unassociatedSubmitter()))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("canonical associated submitter — NOT mill-scope-403 on the schedule endpoint")
  void associatedSubmitter_notForbiddenOnSchedule() throws Exception {
    mockMvc
        .perform(
            get(SCHEDULE1).param("millId", MILL).param("year", YEAR).with(canonicalSubmitter()))
        .andExpect(result -> assertNotEquals(403, result.getResponse().getStatus()));
  }

  @Test
  @DisplayName("admin — NOT mill-scope-403 on the schedule endpoint (tied to no mill)")
  void admin_notForbiddenOnSchedule() throws Exception {
    mockMvc
        .perform(get(SCHEDULE1).param("millId", MILL).param("year", YEAR).with(admin()))
        .andExpect(result -> assertNotEquals(403, result.getResponse().getStatus()));
  }
}
