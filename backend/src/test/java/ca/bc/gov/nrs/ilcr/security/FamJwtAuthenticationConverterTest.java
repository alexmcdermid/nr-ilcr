package ca.bc.gov.nrs.ilcr.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

class FamJwtAuthenticationConverterTest {
  private final FamJwtAuthenticationConverter converter = new FamJwtAuthenticationConverter();

  private Jwt jwt(String idp, Object roles) {
    return Jwt.withTokenValue("token")
        .header("alg", "RS256")
        .subject("keycloak-uuid")
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(60))
        .claim("identity_provider", idp)
        .claim("idir_username", "JSMITH")
        .claim("bceid_username", "BUSINESS_USER")
        .claim("client_roles", roles)
        .build();
  }

  private List<String> roles(Jwt jwt) {
    return converter.convert(jwt).getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .toList();
  }

  @Test
  void staffRolesAndAuditIdentityArePreserved() {
    var jwt = jwt("azureidir", List.of("ILCR_ADMIN", "ILCR_SUBMITTER"));
    assertThat(roles(jwt)).containsExactly("ADMIN", "SUBMITTER");
    assertThat(converter.convert(jwt).getName()).isEqualTo("JSMITH");
  }

  @Test
  void foreignAndBookkeepingRolesGrantNothing() {
    assertThat(
            roles(
                jwt(
                    "idir",
                    List.of(
                        "ADMIN", "OTHER_ILCR_ADMIN", "CSP_ADMIN", "FAM:EXPIRES:2099:ILCR_ADMIN"))))
        .isEmpty();
  }

  @Test
  void businessIdentityCanOnlyBeASubmitter() {
    var jwt = jwt("bceidbusiness", List.of("ILCR_ADMIN", "ILCR_SUBMITTER"));
    assertThat(roles(jwt)).containsExactly("SUBMITTER");
    assertThat(converter.convert(jwt).getName()).isEqualTo("BUSINESS_USER");
  }

  @Test
  void noAppRoleIsAuthenticatedWithoutEntitlement() {
    assertThat(roles(jwt("idir", List.of()))).isEmpty();
  }

  @Test
  void unsupportedProviderCannotReceiveRoles() {
    assertThat(roles(jwt("bceidbasic", List.of("ILCR_ADMIN", "ILCR_SUBMITTER")))).isEmpty();
  }

  @Test
  void resourceRolesAreReadOnlyFromAuthorizedClient() {
    var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("identity_provider", "idir")
            .claim("idir_username", "JSMITH")
            .claim("azp", "ilcr-browser")
            .claim(
                "resource_access",
                Map.of(
                    "ilcr-browser",
                    Map.of("roles", List.of("ILCR_SUBMITTER")),
                    "other",
                    Map.of("roles", List.of("ILCR_ADMIN"))))
            .build();
    assertThat(roles(jwt)).containsExactly("SUBMITTER");
  }

  @Test
  void legacyCognitoClaimsAreNotAuthorities() {
    var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "none")
            .claim("cognito:groups", List.of("ILCR_ADMIN"))
            .build();
    assertThat(roles(jwt)).isEmpty();
  }
}
