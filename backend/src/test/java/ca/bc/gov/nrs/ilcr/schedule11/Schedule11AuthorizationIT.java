package ca.bc.gov.nrs.ilcr.schedule11;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Story 25.1 acceptance — authorization on {@code VIEW_SCHEDULE} for {@code GET /api/v1/schedule11}
 * (AC8; AD-7). Security ON: drives the real {@code oauth2ResourceServer} chain +
 * {@code @PreAuthorize}, with authorities derived through the production {@link
 * FamJwtAuthenticationConverter} (the {@code jwt()} default reads only the {@code scope} claim, so
 * the converter is plugged into {@code .authorities(...)}) — the established Boot-4 idiom from
 * {@code Schedule1AuthorizationIT}.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/schedule11 — authorization on VIEW_SCHEDULE (AC8)")
class Schedule11AuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule11";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  // jwt() injects the Jwt directly; a mock JwtDecoder only satisfies chain construction (the
  // real FAM decoder wiring is the deferred auth story).
  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no group (empty cognito:groups) -> 403 ProblemDetail")
  void noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", "610")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("foreign group (no ILCR role) -> 403 ProblemDetail")
  void foreignGroup_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", "610")
                .param("year", "2021")
                .with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> passes authz (200 document)")
  void submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT).param("millId", "610").param("year", "2021").with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("ILCR_ADMIN -> passes authz (VIEW_SCHEDULE is role-agnostic in the central map)")
  void admin_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", "610")
                .param("year", "2021")
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful());
  }
}
