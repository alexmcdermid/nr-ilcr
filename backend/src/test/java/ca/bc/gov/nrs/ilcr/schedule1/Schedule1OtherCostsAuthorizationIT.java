package ca.bc.gov.nrs.ilcr.schedule1;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
 * Story 2.4 (AD-7): authorization on EDIT_SCHEDULE for the Other-Costs write verbs. Security ON,
 * real {@code @PreAuthorize} + {@link FamJwtAuthenticationConverter}. A principal without
 * EDIT_SCHEDULE must get 403 {@code problem+json} on POST and DELETE — this catches an
 * action-string or annotation mistake that the security-off {@link Schedule1OtherCostsIT} cannot.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("/api/v1/schedule1/other-costs — authorization on EDIT_SCHEDULE (AD-7)")
class Schedule1OtherCostsAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule1/other-costs";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("no VIEW_SCHEDULE -> GET 403 problem+json")
  void get_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("millId", "523")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE -> POST 403 problem+json")
  void add_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT)
                .param("millId", "524")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{ \"description\": \"x\", \"cost\": 1 }")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE -> DELETE 403 problem+json")
  void delete_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            delete(ENDPOINT + "/5081")
                .param("millId", "526")
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no EDIT_SCHEDULE -> batch PUT (save) 403 problem+json")
  void save_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(ENDPOINT)
                .param("millId", "526")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{ \"rows\": [ { \"id\": 1, \"description\": \"x\", \"cost\": 1 } ] }")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER holds EDIT_SCHEDULE -> POST passes authz (not 403)")
  void add_submitter_passesAuthorization() throws Exception {
    // Dedicated mill 527 so this persisting probe never pollutes the add fixture (524) that the
    // main
    // IT asserts absolute row counts against (both classes share the Testcontainers DB).
    mockMvc
        .perform(
            post(ENDPOINT)
                .param("millId", "527")
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{ \"description\": \"authz probe\", \"cost\": 1 }")
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }
}
