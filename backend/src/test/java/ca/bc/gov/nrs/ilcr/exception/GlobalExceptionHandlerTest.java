package ca.bc.gov.nrs.ilcr.exception;

import static org.assertj.core.api.Assertions.assertThat;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.core.MethodParameter;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

/**
 * Unit coverage for the two {@link GlobalExceptionHandler} branches the PR #266 review changed: the
 * ROW IDENTITY a batch validation failure reports, and the TYPE SCOPING of the converter-message
 * lookup. Both were previously only reachable through the Oracle failsafe ITs, and neither had an
 * assertion at all — the review's "worth a test either way" applies to both.
 *
 * <p>Deliberately a plain unit test: these branches are pure string composition over a {@code
 * BindingResult} / a Jackson cause message, so a container adds cost without adding evidence. The
 * message source is the REAL bundle, so a renamed or deleted key fails here rather than silently
 * degrading to the key name at runtime.
 */
class GlobalExceptionHandlerTest {

  private final GlobalExceptionHandler handler = new GlobalExceptionHandler(realBundle());

  private static ResourceBundleMessageSource realBundle() {
    ResourceBundleMessageSource source = new ResourceBundleMessageSource();
    source.setBasename("messages");
    source.setDefaultEncoding("UTF-8");
    return source;
  }

  /** Only needed to satisfy {@link MethodParameter}; never invoked. */
  @SuppressWarnings("unused")
  private void batchEndpoint(Object body) {
    // no-op
  }

  private MethodArgumentNotValidException validationFailure(FieldError... fieldErrors)
      throws NoSuchMethodException {
    BindingResult binding = new BeanPropertyBindingResult(new Object(), "request");
    for (FieldError error : fieldErrors) {
      binding.addError(error);
    }
    Method method =
        GlobalExceptionHandlerTest.class.getDeclaredMethod("batchEndpoint", Object.class);
    return new MethodArgumentNotValidException(new MethodParameter(method, 0), binding);
  }

  private static FieldError at(String path, String message) {
    return new FieldError("request", path, null, false, null, null, message);
  }

  private String detailOf(ResponseEntity<ProblemDetail> response) {
    ProblemDetail problem = response.getBody();
    assertThat(problem).isNotNull();
    return problem.getDetail();
  }

  @Test
  @DisplayName("access denied audit line carries actor + action, and never a credential/token")
  void accessDeniedAuditLineCarriesActorAndAction() {
    // Story 5.4 AC4/NFR3: the denial audit line names the actor + action (timestamp is the log
    // line's own), and never the credential or a token.
    String line =
        GlobalExceptionHandler.deniedAuditMessage(
            new UsernamePasswordAuthenticationToken("IDIRJDOE", "N/A", List.of()),
            new MockHttpServletRequest("POST", "/api/v1/code-tables/UNIT_CODE/entries"),
            "Access Denied");

    assertThat(line)
        .contains("Authorization denied")
        .contains("IDIRJDOE")
        .contains("POST")
        .contains("/api/v1/code-tables/UNIT_CODE/entries");
    // The credential ("N/A") is never logged; nor is any bearer token (NFR3).
    assertThat(line).doesNotContain("N/A");
    assertThat(line.toLowerCase(Locale.ROOT)).doesNotContain("bearer");
  }

  @Test
  @DisplayName("access denied audit line renders an unauthenticated caller as 'anonymous'")
  void accessDeniedAuditLineAnonymousWhenNoAuth() {
    String line =
        GlobalExceptionHandler.deniedAuditMessage(
            null, new MockHttpServletRequest("GET", "/api/v1/code-tables"), "Access Denied");
    assertThat(line).contains("actor=anonymous").contains("GET").contains("/api/v1/code-tables");
  }

  @Test
  @DisplayName("audit actor for a CSS Jwt is its directory username, never the subject")
  void accessDeniedAuditActorFromRealJwtPrincipal() {
    // The production principal name comes from
    // FamJwtAuthenticationConverter
    // (the directory username, never the subject UUID) — prove the audit actor tracks it, so a
    // converter
    // change can't silently start auditing under the opaque Keycloak sub.
    var converter = new FamJwtAuthenticationConverter();
    Jwt withUsername =
        Jwt.withTokenValue("t")
            .claim("identity_provider", "azureidir")
            .header("alg", "none")
            .claim("idir_username", "IDIRJDOE")
            .claim("sub", "cognito-uuid-123")
            .build();
    String line =
        GlobalExceptionHandler.deniedAuditMessage(
            converter.convert(withUsername),
            new MockHttpServletRequest("POST", "/api/v1/code-tables/UNIT_CODE/entries"),
            "Access Denied");
    assertThat(line).contains("actor=IDIRJDOE").doesNotContain("cognito-uuid-123");

    Jwt withoutUsername =
        Jwt.withTokenValue("t").header("alg", "none").claim("sub", "cognito-uuid-123").build();
    String fallback =
        GlobalExceptionHandler.deniedAuditMessage(
            converter.convert(withoutUsername),
            new MockHttpServletRequest("GET", "/api/v1/code-tables"),
            "Access Denied");
    assertThat(fallback).contains("actor=anonymous").doesNotContain("cognito-uuid-123");
  }

  @Test
  @DisplayName("audit line neutralizes CR/LF/quote in the request path (no log forging)")
  void accessDeniedAuditLineSanitizesControlChars() {
    // A crafted URI carrying a newline + quote must not break the single-line action="..." field
    // or inject a second fake 'Authorization denied' line.
    MockHttpServletRequest crafted =
        new MockHttpServletRequest("GET", "/api/v1/x\"\nAuthorization denied: actor=admin");
    String line =
        GlobalExceptionHandler.deniedAuditMessage(
            new UsernamePasswordAuthenticationToken("IDIRJDOE", "N/A", List.of()),
            crafted,
            "Access Denied");
    assertThat(line).doesNotContain("\n").doesNotContain("\r");
    // The literal control/quote characters are neutralized to underscores.
    assertThat(line).contains("actor=IDIRJDOE");
  }

  @Test
  @DisplayName("a batch entry's failure names its row: 'Id: {n} - ' from the collection index")
  void batchFailureCarriesTheRowLabel() throws Exception {
    // culverts[6] is the SEVENTH entry, so the legacy label reads Id: 7 — legacy quoted the 1-based
    // rowCounter (schedule7B.xhtml:436-437). Without the prefix a 20-culvert Save answered with the
    // bare sentence and rolled the whole batch back, leaving the reporter to find the row by hand.
    var response =
        handler.handleMethodArgumentNotValid(
            validationFailure(
                at(
                    "culverts[6].culvert.installCost",
                    "Entered cost must be between -99,999,999 and 99,999,999.")),
            new MockHttpServletRequest("PUT", "/api/v1/schedule7b/culverts"));

    assertThat(detailOf(response))
        .isEqualTo("Id: 7 - Entered cost must be between -99,999,999 and 99,999,999.");
  }

  @Test
  @DisplayName("two rows failing the SAME way stay distinguishable, one line each")
  void twoRowsFailingAlikeAreNotCollapsed() throws Exception {
    // The whole point of carrying the index: identical sentences used to join into
    // "<msg>; <msg>" with nothing to tell the rows apart.
    var response =
        handler.handleMethodArgumentNotValid(
            validationFailure(
                at("culverts[0].culvert.materialCost", "Entered cost is invalid."),
                at("culverts[3].culvert.materialCost", "Entered cost is invalid.")),
            new MockHttpServletRequest("PUT", "/api/v1/schedule7b/culverts"));

    assertThat(detailOf(response))
        .isEqualTo("Id: 1 - Entered cost is invalid.; Id: 4 - Entered cost is invalid.");
  }

  @Test
  @DisplayName("the SAME row and message twice collapses to one line, never a doubled sentence")
  void identicalPairsCollapse() throws Exception {
    var response =
        handler.handleMethodArgumentNotValid(
            validationFailure(
                at("culverts[0].culvert.comments", "Comments must be 3500 characters or fewer."),
                at("culverts[0].culvert.comments", "Comments must be 3500 characters or fewer.")),
            new MockHttpServletRequest("PUT", "/api/v1/schedule7b/culverts"));

    // Still row-labelled — it is an indexed path — but ONE line, not the sentence twice.
    assertThat(detailOf(response)).isEqualTo("Id: 1 - Comments must be 3500 characters or fewer.");
  }

  @Test
  @DisplayName("a single-record body is UNPREFIXED — the legacy Add form carried no row label")
  void singleRecordFailureIsUnprefixed() throws Exception {
    // Guards the blast radius: every non-batch endpoint in the app shares this handler, and legacy
    // put
    // the prefix on list rows only (schedule7B.xhtml:177-178,187-188 vs :436-437,455-456).
    var response =
        handler.handleMethodArgumentNotValid(
            validationFailure(at("culvertPieceCount", "Value Required")),
            new MockHttpServletRequest("POST", "/api/v1/schedule7b/culverts"));

    assertThat(detailOf(response)).isEqualTo("Value Required");
  }

  @Test
  @DisplayName(
      "ANOTHER schedule's indexed batch is UNPREFIXED — the label is 7B's, not a house style")
  void foreignBatchFailureIsUnprefixed() throws Exception {
    // Indexed-ness alone is not the trigger. Every schedule takes an indexed batch body — lineItems
    // (1, 3), rows (1, 3, 5), categories (4) — and none of their legacy screens carried a row
    // label,
    // so a prefix keyed on "[n]" alone rewrote four schedules' 400 wording at once. That is exactly
    // what happened: Schedule1WriteIT, Schedule4WriteIT and Schedule5SubPageValidationIT all pin
    // the
    // bare sentence and all went red once CI ran the ITs (PR #268). Deleting the scope check here
    // brings them back, which is the point of this test.
    var schedule5Row =
        handler.handleMethodArgumentNotValid(
            validationFailure(
                at("rows[0].description", "Description must be 30 characters or fewer.")),
            new MockHttpServletRequest("PUT", "/api/v1/schedule5/camps/8700/other-camp-expenses"));
    assertThat(detailOf(schedule5Row)).isEqualTo("Description must be 30 characters or fewer.");

    var schedule1LineItem =
        handler.handleMethodArgumentNotValid(
            validationFailure(
                at(
                    "lineItems[0].cost",
                    "Entered cost must be between -99,999,999 and 99,999,999.")),
            new MockHttpServletRequest("PUT", "/api/v1/schedule1"));
    assertThat(detailOf(schedule1LineItem))
        .isEqualTo("Entered cost must be between -99,999,999 and 99,999,999.");
  }

  @Test
  @DisplayName("the converter lookup is scoped to the OWNING TYPE, not the bare field name")
  void converterKeyIsTypeScoped() {
    // Jackson's reference chain names the target type. Matching "spanSize" alone meant the next DTO
    // to
    // declare one silently inherited culvert wording, with the guard living only in a comment.
    var culvertSpan =
        handler.handleNotReadable(
            notReadable(
                "Cannot deserialize value of type `java.lang.Integer` from String \"abc\""
                    + " (through reference chain:"
                    + " ca.bc.gov.nrs.ilcr.schedule7b.dto.CulvertRequest[\"spanSize\"])"),
            new MockHttpServletRequest("POST", "/api/v1/schedule7b/culverts"));
    assertThat(detailOf(culvertSpan)).isEqualTo("Entered span is invalid.");

    // A DIFFERENT type's spanSize must NOT get culvert wording — it falls to the Integer default.
    var foreignSpan =
        handler.handleNotReadable(
            notReadable(
                "Cannot deserialize value of type `java.lang.Integer` from String \"abc\""
                    + " (through reference chain:"
                    + " ca.bc.gov.nrs.ilcr.somewhere.dto.OtherRequest[\"spanSize\"])"),
            new MockHttpServletRequest("POST", "/api/v1/somewhere"));
    assertThat(detailOf(foreignSpan)).isEqualTo("Entered cost is invalid.");
  }

  @Test
  @DisplayName("a batch entry's converter failure still resolves the field-specific message")
  void converterKeyResolvesThroughTheBatchReferenceChain() {
    // The batch chain prefixes the collection hops; the match is a substring so it still lands.
    var response =
        handler.handleNotReadable(
            notReadable(
                "Cannot deserialize value of type `java.lang.Integer` from String \"x\""
                    + " (through reference chain:"
                    + " ca.bc.gov.nrs.ilcr.schedule7b.dto.CulvertSaveAllRequest[\"culverts\"]"
                    + "->java.util.ArrayList[0]"
                    + "->ca.bc.gov.nrs.ilcr.schedule7b.dto.CulvertSaveAllRequest$Item[\"culvert\"]"
                    + "->ca.bc.gov.nrs.ilcr.schedule7b.dto.CulvertRequest[\"culvertPieceCount\"])"),
            new MockHttpServletRequest("PUT", "/api/v1/schedule7b/culverts"));

    assertThat(detailOf(response)).isEqualTo("Entered number of pieces is invalid.");
  }

  @Test
  @DisplayName("multi-message responses resolve per-message legacy arguments")
  void multiMessageArgumentsAreResolved() {
    var response =
        handler.handleMultiMessage(
            new MultiMessageException(
                org.springframework.http.HttpStatus.CONFLICT,
                List.of("noActiveMillsForNewYearMsg", "reportingPeriodNotFoundMsg"),
                new Object[] {"2025", "2026"},
                new Object[0]),
            new MockHttpServletRequest("POST", "/api/v1/reporting-years"));

    assertThat(detailOf(response))
        .isEqualTo(
            "Any active Mill found for the current Reporting Year 2025 to generate a new Reporting Year 2026.; No reporting periods were found.");
  }

  private static HttpMessageNotReadableException notReadable(String causeMessage) {
    return new HttpMessageNotReadableException(
        "JSON parse error", new IllegalArgumentException(causeMessage), null);
  }
}
