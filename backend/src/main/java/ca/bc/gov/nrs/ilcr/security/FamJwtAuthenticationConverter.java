package ca.bc.gov.nrs.ilcr.security;

import ca.bc.gov.nrs.ilcr.dto.base.Role;
import ca.bc.gov.nrs.ilcr.util.JwtPrincipalUtil;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

/**
 * Converts only the ILCR client's FAM roles, preserving short audit names and mill assignment
 * checks.
 */
@Component
public class FamJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    var authorities =
        FamTokenClaims.applicationRoles(jwt.getClaims()).stream()
            .map(Role::fromValue)
            .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(role.name()))
            .toList();
    return new JwtAuthenticationToken(jwt, authorities, JwtPrincipalUtil.getAuditUsername(jwt));
  }
}
