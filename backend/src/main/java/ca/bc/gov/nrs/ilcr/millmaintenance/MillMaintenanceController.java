package ca.bc.gov.nrs.ilcr.millmaintenance;

import ca.bc.gov.nrs.ilcr.millmaintenance.api.MillMaintenanceApi;
import ca.bc.gov.nrs.ilcr.millmaintenance.dto.AdminMill;
import ca.bc.gov.nrs.ilcr.millmaintenance.dto.AdminMillResponse;
import ca.bc.gov.nrs.ilcr.millmaintenance.dto.ChangeMillStatusRequest;
import ca.bc.gov.nrs.ilcr.millmaintenance.dto.ContactOption;
import ca.bc.gov.nrs.ilcr.millmaintenance.dto.ImportableMill;
import ca.bc.gov.nrs.ilcr.millmaintenance.dto.MillSearchResponse;
import ca.bc.gov.nrs.ilcr.millmaintenance.dto.SaveMillContactsRequest;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP surface for mill administration (UC-MILL-001). Adds authorization and message resolution to
 * {@link MillMaintenanceApi}; never touches the repository directly, and holds no business rules.
 */
@RestController
@ConditionalOnProperty(name = "ilcr.datasource.enabled", havingValue = "true")
public class MillMaintenanceController implements MillMaintenanceApi {

  private static final String MAINTAIN_MILLS =
      "@permissions.hasPermission(authentication, 'MAINTAIN_MILLS')";

  private final MillMaintenanceService service;
  private final MessageSource messageSource;

  /**
   * Constructs the controller.
   *
   * @param service the mill administration service
   * @param messageSource the single message bundle
   */
  public MillMaintenanceController(MillMaintenanceService service, MessageSource messageSource) {
    this.service = service;
    this.messageSource = messageSource;
  }

  @Override
  @PreAuthorize(MAINTAIN_MILLS)
  public ResponseEntity<MillSearchResponse> search(
      String millNumber, String millName, String status, Authentication authentication) {
    List<AdminMill> results = service.search(millNumber, millName, status);
    if (results.isEmpty()) {
      // A zero-match search is not a failed request: the criteria stay on screen for another
      // attempt, so the message rides a 200 rather than an error status (S11).
      return ResponseEntity.ok(
          new MillSearchResponse(
              results,
              MillMaintenanceService.MSG_NOT_FOUND,
              resolve(MillMaintenanceService.MSG_NOT_FOUND)));
    }
    return ResponseEntity.ok(MillSearchResponse.of(results));
  }

  @Override
  @PreAuthorize(MAINTAIN_MILLS)
  public ResponseEntity<List<ImportableMill>> findImportable(
      String millNumber, String millName, Authentication authentication) {
    return ResponseEntity.ok(service.findImportable(millNumber, millName));
  }

  @Override
  @PreAuthorize(MAINTAIN_MILLS)
  public ResponseEntity<AdminMill> findById(long millId, Authentication authentication) {
    return ResponseEntity.ok(service.findById(millId));
  }

  @Override
  @PreAuthorize(MAINTAIN_MILLS)
  public ResponseEntity<List<ContactOption>> contactOptions(
      long millId, Authentication authentication) {
    return ResponseEntity.ok(service.contactOptions(millId));
  }

  @Override
  @PreAuthorize(MAINTAIN_MILLS)
  public ResponseEntity<AdminMillResponse> importMill(long millId, Authentication authentication) {
    return ResponseEntity.ok(toResponse(service.importMill(millId, actingUser(authentication))));
  }

  @Override
  @PreAuthorize(MAINTAIN_MILLS)
  public ResponseEntity<AdminMillResponse> activate(
      long millId, ChangeMillStatusRequest request, Authentication authentication) {
    return ResponseEntity.ok(
        toResponse(service.activate(millId, request.revisionCount(), actingUser(authentication))));
  }

  @Override
  @PreAuthorize(MAINTAIN_MILLS)
  public ResponseEntity<AdminMillResponse> deactivate(
      long millId, ChangeMillStatusRequest request, Authentication authentication) {
    return ResponseEntity.ok(
        toResponse(
            service.deactivate(millId, request.revisionCount(), actingUser(authentication))));
  }

  @Override
  @PreAuthorize(MAINTAIN_MILLS)
  public ResponseEntity<AdminMillResponse> saveContacts(
      long millId, SaveMillContactsRequest request, Authentication authentication) {
    return ResponseEntity.ok(
        toResponse(
            service.saveContacts(
                millId,
                request.headOfficeContactInd(),
                request.headOfficeContactId(),
                request.divisionContactId(),
                request.revisionCount(),
                actingUser(authentication))));
  }

  /**
   * Pair a write outcome with its resolved message. All the confirmations take the same two
   * arguments in the same order — the mill number then its name — so one mapping serves them. A
   * null key stays null on the wire (Jackson omits it): import has no legacy confirmation sentence,
   * its screen confirmed by displaying the mill's details.
   */
  private AdminMillResponse toResponse(MillMaintenanceService.Outcome outcome) {
    AdminMill mill = outcome.mill();
    if (outcome.messageKey() == null) {
      return new AdminMillResponse(mill, null, null);
    }
    return new AdminMillResponse(
        mill,
        outcome.messageKey(),
        resolve(outcome.messageKey(), mill.millNumber(), mill.millName()));
  }

  private String resolve(String key, Object... args) {
    return messageSource.getMessage(key, args, key, LocaleContextHolder.getLocale());
  }

  /**
   * The acting administrator's identifier for the audit columns — the raw {@code
   * custom:idp_username} claim, read without any fallback: every substitute identity (the 32-char
   * directory GUID, the 36-char {@code sub}) overflows the 30-character audit columns and would
   * fail as an opaque ORA-12899 deep inside the write, so a real token without the claim is refused
   * here, where the broken identity contract can be named.
   *
   * <p>With security off there is no token, so the mock principal's name is used instead; that only
   * ever happens in local development.
   */
  private static String actingUser(Authentication authentication) {
    if (authentication instanceof JwtAuthenticationToken jwtAuth) {
      String username =
          ca.bc.gov.nrs.ilcr.util.JwtPrincipalUtil.getAuditUsername(jwtAuth.getToken());
      if (StringUtils.isBlank(username)) {
        throw new IllegalStateException(
            "token carries no custom:idp_username to stamp the audit columns");
      }
      return username;
    }
    return authentication.getName();
  }
}
