package ca.bc.gov.nrs.ilcr.messages;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
 * Acceptance test for authorization on VIEW_SCHEDULE for {@code GET /api/v1/messages} (review fix
 * 2026-08-11). The endpoint's only other test is standalone MockMvc, which never engages method
 * security — its {@code @PreAuthorize} could be deleted or the permission name typo'd and every
 * unit test would stay green. Security ON; drives the real {@code oauth2ResourceServer} chain +
 * {@code @PreAuthorize} through the PRODUCTION {@link FamJwtAuthenticationConverter}, mirroring the
 * sibling {@code *AuthorizationIT}s.
 *
 * <p>The authorized cases double as the production-context pin the standalone test cannot give:
 * resolution and the missing-key 404 run against Boot's auto-configured {@code MessageSource}
 * (default basename {@code messages}, {@code useCodeAsDefaultMessage=false}). A {@code
 * use-code-as-default-message=true} misconfiguration would defeat the missing-key guard — the key
 * would echo back as text instead of throwing — while the hand-built unit-test source stayed green;
 * here it fails the 404 case.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/messages — authorization on VIEW_SCHEDULE")
class MessageAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/messages";
  private static final String COPY_KEY = "sch5.copy.msg";

  /** SUC-001, added to the allowlist by the Data Extract CSV story. */
  private static final String EXTRACT_SUCCESS_KEY = "dataExtractedSuccesfullyInfoMsg";

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
        .perform(get(ENDPOINT).param("key", COPY_KEY).with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("foreign group (no ILCR_ prefix) -> 403")
  void foreignGroup_returns403() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("key", COPY_KEY)
                .with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> 200 with the PRODUCTION MessageSource's resolved text")
  void submitter_resolvesThroughProductionBundle() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("key", COPY_KEY)
                .param("arg", "Cedar Flats Camp")
                .with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.key").value(COPY_KEY))
        .andExpect(
            jsonPath("$.text")
                .value(
                    "To complete copy of Camp: Cedar Flats Camp, "
                        + "provide a new Camp Name and invoke save."));
  }

  @Test
  @DisplayName("the Data Extract success key resolves for BOTH roles, like the others")
  void extractSuccessKeyResolvesForBothRoles() throws Exception {
    // Added to the allowlist by the Data Extract CSV story. The extract endpoint itself is
    // ADMIN-only, but this key is gated on VIEW_SCHEDULE like every other entry — it is a static
    // sentence, not admin data, and narrowing the gate per key would invent a second rule for no
    // benefit. A submitter can fetch the sentence and has no endpoint to use it on.
    mockMvc
        .perform(get(ENDPOINT).param("key", EXTRACT_SUCCESS_KEY).with(canonicalSubmitter()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.text").value("Data extraction successfully."));

    mockMvc
        .perform(
            get(ENDPOINT)
                .param("key", EXTRACT_SUCCESS_KEY)
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.key").value(EXTRACT_SUCCESS_KEY))
        .andExpect(jsonPath("$.text").value("Data extraction successfully."));
  }

  @Test
  @DisplayName("ILCR_ADMIN, unknown key -> 404 whose detail is the bundle text, never the key")
  void admin_unknownKey404sWithBundleDetail() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("key", "noSuchKeyAnywhere")
                .with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.detail").value("Message not found."));
  }
}
