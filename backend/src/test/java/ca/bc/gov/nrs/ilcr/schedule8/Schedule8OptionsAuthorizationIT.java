package ca.bc.gov.nrs.ilcr.schedule8;

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
 * Acceptance test for authorization on VIEW_SCHEDULE (AD-7) for the Schedule 8 page-editor option
 * lists. The {@code /options} endpoint serves global reference data (no mill/year context), so it
 * is gated only by the same VIEW_SCHEDULE permission as the read — mirrors {@link
 * Schedule8AuthorizationIT}.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/schedule8/options — authorization on VIEW_SCHEDULE (AD-7)")
class Schedule8OptionsAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule8/options";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no VIEW_SCHEDULE (empty cognito:groups) -> 403")
  void noPermission_returns403() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("foreign group (no ILCR_ suffix) -> 403")
  void foreignGroup_returns403() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER group -> passes authz (200)")
  void submitter_passesAuthorization() throws Exception {
    mockMvc.perform(get(ENDPOINT).with(canonicalSubmitter())).andExpect(status().isOk());
  }

  @Test
  @DisplayName("ILCR_ADMIN group -> passes authz (200)")
  void admin_passesAuthorization() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isOk());
  }
}
