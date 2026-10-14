package ca.bc.gov.nrs.ilcr.user;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test for {@code GET /api/v1/me} with security ON. Drives the real {@code
 * oauth2ResourceServer} chain and the production {@link FamJwtAuthenticationConverter} so {@code
 * /me.roles} is proven to come from the same authorities method security reads (the
 * standalone-converter bug this guards against would let {@code /me} and {@code @PreAuthorize}
 * disagree). The decoder is mocked because the {@code jwt()} post-processor injects a
 * pre-authenticated principal and never decodes.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/me — security on")
class UserMeIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/me";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private static RequestPostProcessor famJwt(List<String> groups, Consumer<Jwt.Builder> claims) {
    return jwt()
        .jwt(
            builder -> {
              builder.claim("identity_provider", "azureidir").claim("client_roles", groups);
              claims.accept(builder);
            })
        .authorities(jwt -> CONVERTER.convert(jwt).getAuthorities());
  }

  private static RequestPostProcessor famJwt(List<String> groups) {
    return famJwt(groups, builder -> {});
  }

  @Test
  @DisplayName("ILCR_ADMIN token -> 200 with role and identity from the ID-token claims")
  void adminToken_returnsAdminRoleAndIdentity() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .with(
                    famJwt(
                        List.of("ILCR_ADMIN"),
                        builder ->
                            builder
                                .claim("idir_user_guid", "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4")
                                .claim("display_name", "Doe, John")
                                .claim("identity_provider", "idir")
                                .claim("email", "john.doe@gov.bc.ca"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userGuid").value("A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4"))
        .andExpect(jsonPath("$.displayName").value("Doe, John"))
        .andExpect(jsonPath("$.email").value("john.doe@gov.bc.ca"))
        .andExpect(jsonPath("$.identityProvider").value("IDIR"))
        .andExpect(jsonPath("$.roles", contains("ILCR_ADMIN")));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER token -> roles = [ILCR_SUBMITTER]")
  void submitterToken_returnsSubmitterRole() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(famJwt(List.of("ILCR_SUBMITTER"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.roles", contains("ILCR_SUBMITTER")));
  }

  @Test
  @DisplayName("both ILCR groups -> both roles")
  void bothGroups_returnsBothRoles() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(famJwt(List.of("ILCR_ADMIN", "ILCR_SUBMITTER"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.roles", containsInAnyOrder("ILCR_ADMIN", "ILCR_SUBMITTER")));
  }

  @Test
  @DisplayName("no token -> 401")
  void noToken_returns401() throws Exception {
    mockMvc.perform(get(ENDPOINT)).andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("valid token with no ILCR group -> 200 with empty roles (no 401 loop)")
  void noIlcrGroup_returns200WithEmptyRoles() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .with(
                    famJwt(
                        List.of("SOME_OTHER_APP_ADMIN"),
                        builder ->
                            builder.claim("idir_user_guid", "GUIDNOACCESS0000000000000000000A"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userGuid").value("GUIDNOACCESS0000000000000000000A"))
        .andExpect(jsonPath("$.roles", empty()));
  }

  @Test
  @DisplayName(
      "minimal CSS profile keeps directory identity when optional name/email claims are absent")
  void minimalCssProfileDoesNotError() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .with(
                    famJwt(
                        List.of("ILCR_SUBMITTER"),
                        builder ->
                            builder
                                .subject("keycloak-user-uuid")
                                .claim("idir_username", "JSMITH")
                                .claim("idir_user_guid", "0123456789abcdef0123456789abcdef"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userGuid").value("0123456789ABCDEF0123456789ABCDEF"))
        .andExpect(jsonPath("$.displayName").value("0123456789ABCDEF0123456789ABCDEF"))
        .andExpect(jsonPath("$.identityProvider").value("IDIR"))
        .andExpect(jsonPath("$.roles", contains("ILCR_SUBMITTER")));
  }

  @Test
  @DisplayName("O4: a domain endpoint is not public once security is on -> 401 unauthenticated")
  void domainEndpoint_unauthenticated_returns401() throws Exception {
    mockMvc.perform(get("/api/v1/mills")).andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("AC3: /me.roles agrees with @PreAuthorize — submitter is 403 on the admin endpoint")
  void submitterRolesAgreeWithMethodSecurity() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(famJwt(List.of("ILCR_SUBMITTER"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.roles", contains("ILCR_SUBMITTER")));

    mockMvc
        .perform(get("/api/v1/code-tables").with(famJwt(List.of("ILCR_SUBMITTER"))))
        .andExpect(status().isForbidden());
  }
}
