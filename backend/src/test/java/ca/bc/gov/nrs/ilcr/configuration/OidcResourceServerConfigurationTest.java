package ca.bc.gov.nrs.ilcr.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * The FAM decoder factory in isolation. The acceptance tests mock the {@link JwtDecoder} (the
 * {@code jwt()} post-processor never decodes), so the bean method itself is exercised here — the
 * configured happy path and the fail-closed guard that refuses to start without a client id.
 */
class OidcResourceServerConfigurationTest {

  private static final String JWKS =
      "https://cognito-idp.ca-central-1.amazonaws.com/ca-central-1_pool/.well-known/jwks.json";
  private static final String ISSUER =
      "https://cognito-idp.ca-central-1.amazonaws.com/ca-central-1_pool";

  private final OidcResourceServerConfiguration configuration =
      new OidcResourceServerConfiguration();

  @Test
  @DisplayName("builds a JwtDecoder when the client id (authorized party) is configured")
  void buildsDecoderWhenAudienceConfigured() {
    JwtDecoder decoder = configuration.jwtDecoder(JWKS, ISSUER, "web-client-id");

    assertThat(decoder).isNotNull();
  }

  @Test
  @DisplayName(
      "fails closed (IllegalStateException) when security is on but the client id is unset")
  void throwsWhenAudienceMissing() {
    assertThatThrownBy(() -> configuration.jwtDecoder(JWKS, ISSUER, "   "))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ILCR_OIDC_CLIENT_ID");
  }
}
