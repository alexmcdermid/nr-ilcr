package ca.bc.gov.nrs.ilcr.security;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** CSS claims shared by token validation, role conversion, and ILCR's directory/audit accessors. */
public final class FamTokenClaims {
  private FamTokenClaims() {}

  public static String string(Map<String, Object> claims, String key) {
    return claims.get(key) instanceof String value ? value.trim() : "";
  }

  public static boolean isStaff(Map<String, Object> claims) {
    return Set.of("idir", "azureidir").contains(string(claims, "identity_provider"));
  }

  public static boolean isBusiness(Map<String, Object> claims) {
    return "bceidbusiness".equals(string(claims, "identity_provider"));
  }

  public static String username(Map<String, Object> claims) {
    return string(claims, isBusiness(claims) ? "bceid_username" : "idir_username");
  }

  /** Returns the existing canonical directory GUID, never the Keycloak subject. */
  public static String guid(Map<String, Object> claims) {
    return string(claims, isBusiness(claims) ? "bceid_user_guid" : "idir_user_guid")
        .replace("-", "")
        .toUpperCase(Locale.ROOT);
  }

  /** Reads CSS client roles, falling back only to the authorized client's resource roles. */
  public static List<String> roles(Map<String, Object> claims) {
    List<String> roles = stringRoles(claims.get("client_roles"));
    if (!roles.isEmpty()) {
      return roles;
    }
    if (claims.get("resource_access") instanceof Map<?, ?> clients
        && clients.get(string(claims, "azp")) instanceof Map<?, ?> client) {
      return stringRoles(client.get("roles"));
    }
    return List.of();
  }

  /** Keeps only exact ILCR capabilities compatible with the signed identity provider. */
  public static List<String> applicationRoles(Map<String, Object> claims) {
    return roles(claims).stream()
        .filter(
            role ->
                (isStaff(claims) && "ILCR_ADMIN".equals(role))
                    || ((isStaff(claims) || isBusiness(claims)) && "ILCR_SUBMITTER".equals(role)))
        .toList();
  }

  private static List<String> stringRoles(Object claim) {
    return claim instanceof List<?> values
        ? values.stream()
            .filter(String.class::isInstance)
            .map(value -> ((String) value).trim().toUpperCase(Locale.ROOT))
            .filter(role -> !role.isBlank())
            .toList()
        : List.of();
  }
}
