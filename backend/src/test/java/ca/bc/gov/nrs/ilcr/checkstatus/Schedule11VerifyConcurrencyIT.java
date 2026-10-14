package ca.bc.gov.nrs.ilcr.checkstatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import ca.bc.gov.nrs.ilcr.millcontext.MillContextService;
import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Acceptance test — Story 26.3 AC 5: two concurrent Schedule 11 verifies for the same mill/year
 * give exactly one 200 and one 409 {@code reportSubmissionErrorMsg}.
 *
 * <p>Verify takes no row lock (D4, legacy's position), so unlike the submit's race there is no lock
 * to park a thread on. The barrier is placed on the one read both requests must make: each racer's
 * unlocked {@code findTrackStatusCodes} returns only once BOTH have read, so both see {@code S},
 * both pass the gate, and both reach the status UPDATE. That UPDATE's {@code expectedCode}
 * predicate is then the only thing deciding the outcome: the first commits, the second waits on
 * Oracle's row lock for the first to commit, re-evaluates the predicate against {@code V} and
 * matches zero rows. No fixed sleep anywhere; the latch is released by events, never by time.
 *
 * <p>Owns mill 812 ({@code R__59}); security ON so the auditor is resolved from a real token shape.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName(
    "POST /api/v1/check-status/schedule11/verify — two racing verifies, one commits (26.3)")
class Schedule11VerifyConcurrencyIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/check-status/schedule11/verify";
  private static final String SUBMISSION_ERROR =
      "An error has been found submitting schedules. The error details have been logged. Please"
          + " contact ILCR application support.";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;
  @MockitoSpyBean private MillContextService millContextService;
  @Autowired private JdbcTemplate jdbc;
  private final ObjectMapper json = new ObjectMapper();

  private record Outcome(int status, JsonNode body) {}

  @Test
  @DisplayName("812/2021: both read S, exactly one 200 and one 409; V committed once")
  void twoVerifies_exactlyOneCommits() throws Exception {
    CountDownLatch bothHaveRead = new CountDownLatch(2);
    doAnswer(
            invocation -> {
              Object result = invocation.callRealMethod();
              bothHaveRead.countDown();
              if (!bothHaveRead.await(30, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting for the other verify's read");
              }
              return result;
            })
        .when(millContextService)
        .findTrackStatusCodes(812, 2021);

    Jwt token =
        Jwt.withTokenValue("verify11-race-token")
            .header("alg", "none")
            .subject("26262626-3333-4444-5555-777777777777")
            .claim("idir_user_guid", "VERIFY11ADMIN000111122223333AAA1")
            .claim("idir_username", "verify11racer")
            .claim("identity_provider", "azureidir")
            .claim("client_roles", List.of("ILCR_ADMIN"))
            .build();
    Callable<Outcome> racer =
        () -> {
          MvcResult result =
              mockMvc
                  .perform(
                      post(ENDPOINT)
                          .param("millId", "812")
                          .param("year", "2021")
                          .accept(MediaType.APPLICATION_JSON)
                          .with(authentication(CONVERTER.convert(token))))
                  .andReturn();
          String content = result.getResponse().getContentAsString();
          return new Outcome(
              result.getResponse().getStatus(), content.isBlank() ? null : json.readTree(content));
        };

    // What must not change is read BEFORE the race, not restated as a literal after it.
    Map<String, Object> before = statusRow();

    ExecutorService pool = Executors.newFixedThreadPool(2);
    List<Outcome> outcomes = new ArrayList<>();
    try {
      Future<Outcome> first = pool.submit(racer);
      Future<Outcome> second = pool.submit(racer);
      outcomes.add(first.get(90, TimeUnit.SECONDS));
      outcomes.add(second.get(90, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }

    // Both racers really did read the unmoved S before either wrote; without this the test could
    // pass on two sequential requests, which prove only the ordinary V->V refusal.
    assertThat(bothHaveRead.getCount()).isZero();
    List<Integer> statuses = outcomes.stream().map(Outcome::status).sorted().toList();
    assertThat(statuses).as(outcomes.toString()).containsExactly(200, 409);
    Outcome winner = outcomes.stream().filter(o -> o.status() == 200).findFirst().orElseThrow();
    Outcome loser = outcomes.stream().filter(o -> o.status() == 409).findFirst().orElseThrow();
    assertThat(winner.body().path("message").path("key").asText()).isEqualTo("sch11VerifiedMsg");
    assertThat(loser.body().path("detail").asText()).isEqualTo(SUBMISSION_ERROR);

    Map<String, Object> row = statusRow();
    assertThat(before.get("MILL_SILVICULTUR_STATUS_CODE")).isEqualTo("S");
    assertThat(row.get("MILL_SILVICULTUR_STATUS_CODE")).isEqualTo("V");
    // The 1-10 code and REVISION_COUNT (D3: no bump) are unchanged by the winner and the loser
    // alike.
    assertThat(row.get("ILCR_MILL_REPORT_STATUS_CODE"))
        .isEqualTo(before.get("ILCR_MILL_REPORT_STATUS_CODE"));
    assertThat(((Number) row.get("REVISION_COUNT")).intValue())
        .isEqualTo(((Number) before.get("REVISION_COUNT")).intValue());

    // The loser's transaction rolled back whole: category '11' advanced exactly once.
    Map<String, Object> eleven =
        jdbc.queryForMap(
            "SELECT CATEGORY_STATE_CODE, REVISION_COUNT FROM THE.ILCR_REPORT_CATEGORY"
                + " WHERE ILCR_MILL_ID = 812 AND REPORT_YEAR = 2021 AND ILCR_CATEGORY_ID = '11'");
    assertThat(eleven.get("CATEGORY_STATE_CODE")).isEqualTo("V");
    assertThat(((Number) eleven.get("REVISION_COUNT")).intValue()).isEqualTo(1);
  }

  private Map<String, Object> statusRow() {
    return jdbc.queryForMap(
        "SELECT ILCR_MILL_REPORT_STATUS_CODE, MILL_SILVICULTUR_STATUS_CODE, REVISION_COUNT"
            + " FROM THE.ILCR_MILL_REPORT_STATUS WHERE ILCR_MILL_ID = 812 AND REPORT_YEAR = 2021");
  }
}
