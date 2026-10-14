package ca.bc.gov.nrs.ilcr.configuration;

import ca.bc.gov.nrs.ilcr.BackendConstants;
import ca.bc.gov.nrs.ilcr.dto.base.Role;
import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.security.MockPrincipalFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/** Security configuration for the application. */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

  /**
   * Configures the security filter chain.
   *
   * @param http the HttpSecurity to configure
   * @param securityEnabled whether security is enabled
   * @param mockRoleName the mock role name to use when security is disabled
   * @param mockUserGuid the stand-in directory GUID the mock principal presents, so the
   *     identity-scoped Home mill list (Story 5.5) resolves for a mock submitter instead of
   *     fail-closing to an empty list
   * @param famConverter the converter for FAM client roles
   * @return the configured security filter chain
   * @throws Exception if an error occurs during configuration
   */
  @Bean
  // java:S4502 — Disabling CSRF is safe here: this is a stateless REST API (SessionCreationPolicy
  // .STATELESS below) authenticated by bearer JWTs in the Authorization header, with no session
  // cookie. CSRF requires an ambient credential the browser attaches automatically to a forged
  // cross-site request; a bearer token is not sent automatically, so there is no CSRF surface to
  // protect. Revisit this suppression if cookie- or session-based auth is ever introduced.
  @SuppressWarnings("java:S4502")
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      @Value("${ilcr.security.enabled:false}") boolean securityEnabled,
      @Value("${ilcr.security.mock-role:ILCR_SUBMITTER}") String mockRoleName,
      @Value("${ilcr.security.mock-user-guid:CANONSUBMITTERBBBBCCCCDDDD000001}")
          String mockUserGuid,
      FamJwtAuthenticationConverter famConverter)
      throws Exception {
    http.csrf(AbstractHttpConfigurer::disable)
        // No .cors(...) is configured, and that omission is a DELIBERATE, documented decision
        // (Story 29.14) — not an oversight. The browser talks to ONE origin: the Caddy edge
        // (frontend/Caddyfile) serves the SPA and reverse-proxies /api* to this backend, so the
        // SPA calls the API same-origin and no cross-origin browser request ever reaches it.
        // Combined with the stateless bearer-JWT model — no ambient cookie the browser would
        // attach cross-site, the same reasoning as the CSRF note above — the SAFE default for
        // this threat model is NO CORS. There is deliberately no allowedOrigins("*")/
        // allowCredentials surface here to get wrong. If the SPA is ever served from a DIFFERENT
        // origin, terminate CORS at the gateway/Caddy route (preferred); only if the gateway
        // cannot own it, add a tightly-scoped CorsConfigurationSource (named origin(s), explicit
        // methods/headers, credentials only if actually needed) wired via http.cors(...) HERE —
        // never a permissive wildcard, and never "*" combined with credentials.
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .exceptionHandling(
            exceptions ->
                exceptions.authenticationEntryPoint(
                    (request, response, exception) ->
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED)))
        .headers(
            headers ->
                headers
                    .contentSecurityPolicy(
                        csp ->
                            csp.policyDirectives(
                                "default-src 'self'; "
                                    + "script-src 'self'; "
                                    + "style-src 'self' 'unsafe-inline'; "
                                    + "img-src 'self' data:; "
                                    + "object-src 'none'; "
                                    + "base-uri 'self'; "
                                    + "frame-ancestors 'none'"))
                    .frameOptions(frame -> frame.deny())
                    .httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000)));

    if (securityEnabled) {
      http.oauth2ResourceServer(
              oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(famConverter)))
          .authorizeHttpRequests(
              authorize ->
                  authorize
                      // Same public set as the security-off branch: health/info/metrics stay
                      // reachable (e.g. Prometheus scraping /api/prometheus); everything else
                      // under /api/** requires authentication (O4 — Home renders post-login).
                      .requestMatchers(BackendConstants.PUBLIC_PATHS)
                      .permitAll()
                      .requestMatchers("/api/**")
                      .authenticated()
                      .anyRequest()
                      .authenticated());
    } else {
      // Dev/UAT: seed a mock principal so @PreAuthorize action checks run identically with
      // security off (AD-7). Requests are permitted at the request level; method security
      // still evaluates against the mock authority.
      Role mockRole = Role.fromValue(mockRoleName);
      http.addFilterBefore(
          new MockPrincipalFilter(mockRole != null ? mockRole : Role.SUBMITTER, mockUserGuid),
          UsernamePasswordAuthenticationFilter.class);
      http.authorizeHttpRequests(
          authorize ->
              authorize
                  .requestMatchers(BackendConstants.PUBLIC_PATHS)
                  .permitAll()
                  .anyRequest()
                  .permitAll());
    }

    return http.build();
  }
}
