package ca.bc.gov.nrs.ilcr.security;

import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
 * Story 5.4 (AC5) — standalone authorization coverage for the ADMIN-only actions, on par with the
 * per-schedule {@code *AuthorizationIT} files. Proves the central role&rarr;action map denies a
 * non-admin: an {@code ILCR_SUBMITTER} and an authenticated caller with NO ILCR group both get 403
 * on every admin action; an {@code ILCR_ADMIN} passes the gate. Previously this 403 coverage was
 * embedded inside the functional ITs ({@code CodeTableIT}, {@code ReportingYearIT}, {@code
 * HomeContentIT}); it is normalized here.
 *
 * <p>Actions covered (always-on endpoints): {@code MAINTAIN_CODE_TABLES}, {@code
 * OPEN_REPORTING_YEAR}, {@code EDIT_HOME_CONTENT}. {@code MAINTAIN_USERS} (assignments + user
 * lookup) is behind {@code @ConditionalOnProperty} and stays proven in {@code AssignmentWriteIT} /
 * {@code UserLookupIT}, which enable those flags.
 *
 * <p>Runs with security ON. The {@code groups(...)} idiom maps a {@code cognito:groups} claim to
 * authorities through the real {@link FamJwtAuthenticationConverter}, exactly as production does.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Admin-action authorization — submitter/no-group 403, admin passes (Story 5.4)")
class AdminActionAuthorizationIT extends AbstractOracleIT {

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  private static final String CODE_TABLES = "/api/v1/code-tables";
  private static final String REPORTING_YEARS = "/api/v1/admin/reporting-years";
  private static final String HOME_CONTENT = "/api/v1/home-content";

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor groups(String... groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", List.of(groups)))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER is denied every admin action — 403 ProblemDetail")
  void submitter_forbiddenOnAllAdminActions() throws Exception {
    for (String endpoint : List.of(CODE_TABLES, REPORTING_YEARS, HOME_CONTENT)) {
      mockMvc
          .perform(get(endpoint).with(groups("ILCR_SUBMITTER")))
          .andExpect(status().isForbidden())
          .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
    }
  }

  @Test
  @DisplayName("authenticated caller with NO ILCR group is denied every admin action — 403")
  void noGroup_forbiddenOnAllAdminActions() throws Exception {
    for (String endpoint : List.of(CODE_TABLES, REPORTING_YEARS, HOME_CONTENT)) {
      mockMvc.perform(get(endpoint).with(groups())).andExpect(status().isForbidden());
    }
  }

  @Test
  @DisplayName("ILCR_ADMIN passes the gate and reaches real data on the admin actions")
  void admin_allowedOnAdminActions() throws Exception {
    // Not merely "not 403": assert a real JSON payload (never application/problem+json), with
    // actual
    // rows for code-tables, so a 200-with-empty-body / masked-error regression cannot pass this off
    // as "admin allowed".
    mockMvc
        .perform(get(CODE_TABLES).with(groups("ILCR_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.length()", greaterThanOrEqualTo(1)));
    mockMvc
        .perform(get(REPORTING_YEARS).with(groups("ILCR_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    mockMvc
        .perform(get(HOME_CONTENT).with(groups("ILCR_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
  }
}
