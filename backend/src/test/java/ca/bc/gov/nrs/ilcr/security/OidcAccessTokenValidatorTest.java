package ca.bc.gov.nrs.ilcr.security;

import static org.assertj.core.api.Assertions.assertThat;

import ca.bc.gov.nrs.ilcr.configuration.OidcResourceServerConfiguration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class OidcAccessTokenValidatorTest {
  private Map<String, Object> claims() {
    return new HashMap<>(
        Map.of(
            "azp",
            "ilcr-browser",
            "typ",
            "Bearer",
            "identity_provider",
            "azureidir",
            "idir_username",
            "JSMITH",
            "idir_user_guid",
            "0123456789abcdef0123456789abcdef"));
  }

  private Jwt token(Map<String, Object> claims) {
    return Jwt.withTokenValue("token")
        .header("alg", "RS256")
        .claims(c -> c.putAll(claims))
        .expiresAt(Instant.now().plusSeconds(60))
        .build();
  }

  private boolean rejected(Jwt token) {
    return OidcResourceServerConfiguration.accessTokenValidator("ilcr-browser")
        .validate(token)
        .hasErrors();
  }

  @Test
  void acceptsMfaIdentityAndCanonicalDirectoryGuid() {
    var c = claims();
    assertThat(rejected(token(c))).isFalse();
    assertThat(FamTokenClaims.guid(c)).isEqualTo("0123456789ABCDEF0123456789ABCDEF");
  }

  @Test
  void rejectsOtherClientsIdTokensServiceAccountsAndMissingIdentity() {
    for (var pair :
        Map.of(
                "azp",
                "other-app",
                "typ",
                "ID",
                "identity_provider",
                "bceidbasic",
                "idir_username",
                "",
                "idir_user_guid",
                "not-a-directory-guid")
            .entrySet()) {
      var c = claims();
      c.put(pair.getKey(), pair.getValue());
      assertThat(rejected(token(c))).isTrue();
    }
    var c = claims();
    c.remove("idir_username");
    assertThat(rejected(token(c))).isTrue();
  }

  @Test
  void rejectsTokensWithoutExpiry() {
    var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claims(c -> c.putAll(claims())).build();
    assertThat(rejected(jwt)).isTrue();
  }

  @Test
  void businessGuidAndUsernameRemainDistinctFromKeycloakSubject() {
    var c = claims();
    c.put("identity_provider", "bceidbusiness");
    c.put("bceid_username", "licensee");
    c.put("bceid_user_guid", "ABCDEF0123456789ABCDEF0123456789");
    c.put("sub", "keycloak-uuid");
    assertThat(rejected(token(c))).isFalse();
    assertThat(FamTokenClaims.username(c)).isEqualTo("licensee");
    assertThat(FamTokenClaims.guid(c)).isEqualTo("ABCDEF0123456789ABCDEF0123456789");
  }
}
