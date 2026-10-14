package ca.bc.gov.nrs.ilcr.configuration;

import ca.bc.gov.nrs.ilcr.security.FamTokenClaims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/** Signed CSS access tokens for this environment's public ILCR browser client. */
@Configuration
public class OidcResourceServerConfiguration {
  @Bean
  @ConditionalOnProperty(name = "ilcr.security.enabled", havingValue = "true")
  JwtDecoder jwtDecoder(
      @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri,
      @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
      @Value("${ilcr.security.oidc.client-id:}") String clientId) {
    if (clientId.isBlank() || issuerUri.isBlank()) {
      throw new IllegalStateException(
          "ILCR_OIDC_ISSUER_URI and ILCR_OIDC_CLIENT_ID are required when security is enabled");
    }
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    decoder.setJwtValidator(
        new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefaultWithIssuer(issuerUri), accessTokenValidator(clientId)));
    return decoder;
  }

  /** Requires this browser client's access token with both directory and audit identities. */
  public static OAuth2TokenValidator<Jwt> accessTokenValidator(String clientId) {
    return token -> {
      var claims = token.getClaims();
      if (!clientId.equals(FamTokenClaims.string(claims, "azp"))
          || !"Bearer".equals(FamTokenClaims.string(claims, "typ"))
          || token.getExpiresAt() == null
          || !(FamTokenClaims.isStaff(claims) || FamTokenClaims.isBusiness(claims))
          || FamTokenClaims.username(claims).isBlank()
          || !FamTokenClaims.guid(claims).matches("[0-9A-F]{32}")) {
        return OAuth2TokenValidatorResult.failure(
            new OAuth2Error(
                "invalid_token",
                "An ILCR user access token with a directory and audit identity is required",
                null));
      }
      return OAuth2TokenValidatorResult.success();
    };
  }
}
