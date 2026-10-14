package ca.bc.gov.nrs.ilcr.userlookup;

import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import ca.bc.gov.nrs.ilcr.userlookup.dto.DirectoryUser;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test — the directory-search endpoint (UC-USR-001, Story 2.3), security ON, the
 * outbound client mocked (the real API needs the DL-27 service account, which does not exist yet).
 * Proves the ADMIN gate, the request validation, the ProblemDetail degradation, and that the
 * assignments view neither reads nor needs the directory.
 */
@TestPropertySource(properties = {"ilcr.security.enabled=true", "ilcr.user-lookup.enabled=true"})
@DisplayName("GET /api/v1/users/lookup — directory search (admin-gated, Story 2.3)")
class UserLookupIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/users/lookup";
  private static final String GUID = "AAAABBBBCCCCDDDDEEEEFFFF00001111";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;
  @MockitoBean private UserLookupClient directory;

  @Test
  @DisplayName("an admin IDIR search returns the picker candidates")
  void adminIdirSearchReturnsCandidates() throws Exception {
    when(directory.searchIdir("jane", null, null))
        .thenReturn(List.of(new DirectoryUser(GUID, "Doe, Jane", "JDOE", "IDIR", "Jane", "Doe")));

    mockMvc
        .perform(get(ENDPOINT).param("firstName", "jane").with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(1))
        .andExpect(jsonPath("$[0].userGuid").value(GUID))
        .andExpect(jsonPath("$[0].displayName").value("Doe, Jane"))
        .andExpect(jsonPath("$[0].idpUsername").value("JDOE"))
        .andExpect(jsonPath("$[0].identityProvider").value("IDIR"));
  }

  @Test
  @DisplayName("the identity provider is matched case-insensitively")
  void identityProviderIsCaseInsensitive() throws Exception {
    // Every other test sends exact uppercase, so a regression from equalsIgnoreCase to equals
    // would otherwise go unnoticed until a client sent the lowercase form the API documents.
    when(directory.searchIdir("jane", null, null)).thenReturn(List.of());

    mockMvc
        .perform(get(ENDPOINT).param("idp", "idir").param("firstName", "jane").with(admin()))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("a BCeID exact lookup by GUID routes to the exact operation")
  void bceidExactLookupRoutes() throws Exception {
    when(directory.findBusinessBceid("userGuid", GUID))
        .thenReturn(
            List.of(
                new DirectoryUser(GUID, "Biz, User", "bizuser", "BCEIDBUSINESS", "User", "Biz")));

    mockMvc
        .perform(get(ENDPOINT).param("idp", "BCEIDBUSINESS").param("userGuid", GUID).with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].identityProvider").value("BCEIDBUSINESS"));
  }

  @Test
  @DisplayName("when both BCeID keys arrive, the GUID wins — it is the stronger key")
  void bceidPrefersTheGuidOverTheUsername() throws Exception {
    // The precedence is a one-line comment in the controller; reordering the two branches would
    // silently downgrade the lookup to the weaker username match.
    when(directory.findBusinessBceid("userGuid", GUID))
        .thenReturn(
            List.of(
                new DirectoryUser(GUID, "Biz, User", "bizuser", "BCEIDBUSINESS", "User", "Biz")));

    mockMvc
        .perform(
            get(ENDPOINT)
                .param("idp", "BCEIDBUSINESS")
                .param("userGuid", GUID)
                .param("userId", "someone-else")
                .with(admin()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].idpUsername").value("bizuser"));
  }

  @Test
  @DisplayName("a search with no criteria is rejected — the directory has no list-everyone")
  void blankCriteriaAreRejected() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail").value("At least one search criterion is required."));

    mockMvc
        .perform(get(ENDPOINT).param("idp", "BCEIDBUSINESS").with(admin()))
        .andExpect(status().isBadRequest())
        // Pinned by reason, not only by status: a rejection that blames the identity provider for
        // a missing search value sends the admin to fix the wrong thing.
        .andExpect(jsonPath("$.detail").value("At least one search criterion is required."));
  }

  @Test
  @DisplayName("a criterion too short to search on is rejected")
  void tooShortCriteriaAreRejected() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).param("firstName", "a").with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.detail").value("Each search criterion must be at least 2 characters."));
  }

  @Test
  @DisplayName("a parameter the chosen directory cannot use is rejected, not silently dropped")
  void inapplicableParametersAreRejected() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("idp", "BCEIDBUSINESS")
                .param("firstName", "jane")
                .param("userId", "bizuser")
                .with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.detail")
                .value(
                    "The firstName parameter does not apply to the selected identity provider."));

    mockMvc
        .perform(get(ENDPOINT).param("userGuid", GUID).with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.detail")
                .value("The userGuid parameter does not apply to the selected identity provider."));
  }

  @Test
  @DisplayName("an identity provider the directory does not serve is rejected")
  void unknownIdpIsRejected() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).param("idp", "GITHUB").param("userId", "xy").with(admin()))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.detail").value("The identity provider must be IDIR or BCEIDBUSINESS."));
  }

  @Test
  @DisplayName("a directory outage degrades to a ProblemDetail while assignments keep working")
  void directoryOutageDegradesGracefully() throws Exception {
    when(directory.searchIdir("jane", null, null)).thenThrow(new DirectoryUnavailableException());

    mockMvc
        .perform(get(ENDPOINT).param("firstName", "jane").with(admin()))
        .andExpect(status().isBadGateway())
        .andExpect(
            jsonPath("$.detail")
                .value("The user directory is currently unavailable. Please try again later."));

    // The second half is a real control, not a constant: asserting only that assignments answer
    // 200 would pass whether or not an outage were in progress, because the two endpoints share no
    // bean. What actually needs proving is the INDEPENDENCE -- that serving the assignments view
    // consults the directory not at all, so no directory failure mode can reach it.
    clearInvocations(directory);
    mockMvc
        .perform(get("/api/v1/mills/{millId}/submitters", 514L).with(admin()))
        .andExpect(status().isOk());
    verifyNoInteractions(directory);
  }

  @Test
  @DisplayName("a submitter is denied the directory search")
  void submitterIsDenied() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).param("firstName", "jane").with(submitter()))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("an anonymous caller is denied before any directory work happens")
  void anonymousIsDenied() throws Exception {
    mockMvc.perform(get(ENDPOINT).param("firstName", "jane")).andExpect(status().isUnauthorized());
    verifyNoInteractions(directory);
  }

  private RequestPostProcessor admin() {
    return groups("ILCR_ADMIN");
  }

  private RequestPostProcessor submitter() {
    return groups("ILCR_SUBMITTER");
  }

  private RequestPostProcessor groups(String... groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", List.of(groups)))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }
}
