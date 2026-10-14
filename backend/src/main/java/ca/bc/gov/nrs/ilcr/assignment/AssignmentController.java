package ca.bc.gov.nrs.ilcr.assignment;

import ca.bc.gov.nrs.ilcr.assignment.api.AssignmentApi;
import ca.bc.gov.nrs.ilcr.assignment.dto.AccountResponse;
import ca.bc.gov.nrs.ilcr.assignment.dto.AssignSubmitterRequest;
import ca.bc.gov.nrs.ilcr.assignment.dto.AssignmentResponse;
import ca.bc.gov.nrs.ilcr.assignment.dto.EndAssignmentRequest;
import ca.bc.gov.nrs.ilcr.assignment.dto.MillSubmitter;
import ca.bc.gov.nrs.ilcr.assignment.dto.SetAccountActiveRequest;
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
 * Licensee account and mill-assignment endpoints (UC-USR-001/002). Every method is gated on the
 * ADMIN-only {@code MAINTAIN_USERS} action, so a submitter is denied 403 server-side. Delegates to
 * {@link AssignmentService} and resolves the verbatim legacy message text here, so message text
 * never lives in Java.
 */
@RestController
@ConditionalOnProperty(name = "ilcr.datasource.enabled", havingValue = "true")
public class AssignmentController implements AssignmentApi {

  private static final String MAINTAIN_USERS =
      "@permissions.hasPermission(authentication, 'MAINTAIN_USERS')";

  /**
   * Stands in for the target user's first and last name in the legacy messages until the directory
   * can supply them. The legacy sentences name the user three ways — id, first name, last name —
   * and only the id is knowable from an assignment row, so the name positions render empty rather
   * than being filled with a guess or the GUID repeated.
   */
  private static final String NAME_UNRESOLVED = "";

  private final AssignmentService service;
  private final MessageSource messageSource;

  public AssignmentController(AssignmentService service, MessageSource messageSource) {
    this.service = service;
    this.messageSource = messageSource;
  }

  @Override
  @PreAuthorize(MAINTAIN_USERS)
  public ResponseEntity<List<MillSubmitter>> listByMill(
      long millId, boolean includeEnded, Authentication authentication) {
    return ResponseEntity.ok(service.listByMill(millId, includeEnded));
  }

  @Override
  @PreAuthorize(MAINTAIN_USERS)
  public ResponseEntity<List<MillSubmitter>> listByUser(
      String userGuid, boolean includeEnded, Authentication authentication) {
    return ResponseEntity.ok(service.listByUser(userGuid, includeEnded));
  }

  @Override
  @PreAuthorize(MAINTAIN_USERS)
  public ResponseEntity<AssignmentResponse> assign(
      long millId, AssignSubmitterRequest request, Authentication authentication) {
    AssignmentService.Outcome outcome =
        service.assign(millId, request.userGuid(), actingUser(authentication));
    return ResponseEntity.ok(toResponse(outcome.assignment(), outcome.messageKey()));
  }

  @Override
  @PreAuthorize(MAINTAIN_USERS)
  public ResponseEntity<AssignmentResponse> end(
      long millId, String userGuid, EndAssignmentRequest request, Authentication authentication) {
    MillSubmitter ended =
        service.end(millId, userGuid, request.revisionCount(), actingUser(authentication));
    return ResponseEntity.ok(toResponse(ended, AssignmentService.MSG_ENDED));
  }

  @Override
  @PreAuthorize(MAINTAIN_USERS)
  public ResponseEntity<AccountResponse> setAccountActive(
      String userGuid, SetAccountActiveRequest request, Authentication authentication) {
    AssignmentService.AccountOutcome outcome =
        service.setAccountActive(userGuid, request.active(), actingUser(authentication));
    String message =
        resolve(
            outcome.messageKey(), outcome.account().userGuid(), NAME_UNRESOLVED, NAME_UNRESOLVED);
    return ResponseEntity.ok(new AccountResponse(outcome.account(), outcome.messageKey(), message));
  }

  /**
   * Pair an assignment with its resolved message. The already-assigned warning names the user and
   * the mill; the assign and end confirmations lead with the mill and then name the user, so the
   * two argument orders differ and are not interchangeable.
   */
  private AssignmentResponse toResponse(MillSubmitter assignment, String messageKey) {
    String message =
        AssignmentService.MSG_ALREADY_ASSIGNED.equals(messageKey)
            ? resolve(messageKey, assignment.userGuid(), assignment.millName())
            : resolve(
                messageKey,
                assignment.millNumber(),
                assignment.millName(),
                assignment.userGuid(),
                NAME_UNRESOLVED,
                NAME_UNRESOLVED);
    return new AssignmentResponse(assignment, messageKey, message);
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
