package ca.bc.gov.nrs.ilcr.support;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.oracle.OracleContainer;

/**
 * Shared Testcontainers base for Schedule 1 acceptance ({@code *IT.java}) tests (AD-10). Starts one
 * Oracle-Free container for the whole run, applies the shared test-scope THE snapshot with Flyway's
 * Java API, and exposes a MockMvc wired through the Spring Security filter chain.
 *
 * <p>The container is started and migrated in a static block (once per JVM) rather than via
 * {@code @Container}/{@code @Testcontainers}, and Spring Boot's Flyway auto-run is disabled — Boot
 * 4 split Flyway auto-configuration into a separate module the app deliberately does not depend on
 * (AD-2: no runtime DDL). Connecting as user {@code THE} makes {@code THE.<table>} resolve as the
 * current schema without needing CREATE USER privileges.
 *
 * <p>Spring Boot 4 also moved the servlet {@code @AutoConfigureMockMvc} slice; MockMvc is built
 * explicitly from the {@link WebApplicationContext} with {@code springSecurity()} applied so the
 * real authorization path is exercised (AD-7).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
public abstract class AbstractOracleIT {

  static final OracleContainer ORACLE =
      new OracleContainer("gvenzl/oracle-free:23.9-slim-faststart")
          .withUsername("THE")
          .withPassword("THE");

  static {
    ORACLE.start();
    Flyway.configure()
        .dataSource(ORACLE.getJdbcUrl(), ORACLE.getUsername(), ORACLE.getPassword())
        .locations("classpath:db")
        .load()
        .migrate();
  }

  @Autowired private WebApplicationContext webApplicationContext;

  /** Shared MockMvc for subclasses, wired through the full Spring Security filter chain. */
  protected MockMvc mockMvc;

  /**
   * The canonical test submitter GUID (32-char {@code custom:idp_user_id}), seeded by {@code R__70}
   * as ACTIVELY associated to EVERY seeded mill. Story 5.7 per-endpoint mill-scope enforcement 403s
   * a submitter not associated to the mill they target; security-ON schedule ITs that assert
   * submitter access use {@link #canonicalSubmitter()} so their caller can actually reach the test
   * mill.
   */
  protected static final String CANONICAL_SUBMITTER_GUID = "CANONSUBMITTERBBBBCCCCDDDD000001";

  private static final FamJwtAuthenticationConverter CANONICAL_CONVERTER =
      new FamJwtAuthenticationConverter();

  /**
   * A real-JWT {@code ILCR_SUBMITTER} principal carrying {@link #CANONICAL_SUBMITTER_GUID} — the
   * canonical submitter associated to every seeded mill. Authorities come through the production
   * {@link FamJwtAuthenticationConverter} (a {@code cognito:groups} of {@code ILCR_SUBMITTER}), so
   * the converter path is exercised exactly as before, and the {@code custom:idp_user_id} claim
   * lets the caller pass Story 5.7 mill-scope for any seeded mill. Use this wherever a security-ON
   * IT asserts a submitter can REACH a schedule/mill-context endpoint (the drop-in for the old
   * {@code jwtWithGroups(List.of("ILCR_SUBMITTER"))}). For the DENIED case, use an unassociated
   * GUID.
   *
   * @return the request post-processor injecting the canonical submitter principal
   */
  protected static RequestPostProcessor canonicalSubmitter() {
    return jwt()
        .jwt(
            j ->
                j.claim("identity_provider", "azureidir")
                    .claim("idir_username", "TESTUSER")
                    .claim("idir_user_guid", CANONICAL_SUBMITTER_GUID)
                    .claim("client_roles", java.util.List.of("ILCR_SUBMITTER")))
        .authorities(j -> CANONICAL_CONVERTER.convert(j).getAuthorities());
  }

  @BeforeEach
  void setUpMockMvc() {
    this.mockMvc =
        MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
  }

  /**
   * Perform a request for one of the report/print PDF endpoints.
   *
   * <p>Kept as a named helper even though it is now a plain {@code perform}: it marks which tests
   * are exercising the PDF endpoints, and it is where the async dance used to live, so the reason
   * that dance is gone belongs here rather than in a commit message.
   *
   * <p>These endpoints no longer answer with {@code StreamingResponseBody}. The export now finishes
   * BEFORE the response is built, so the body is a spooled file served as a {@link
   * org.springframework.core.io.Resource} on the request thread — nothing is deferred to an async
   * dispatch, and asserting {@code asyncStarted()} would now fail. Writing from an async thread
   * while the response declared a {@code Content-Length} is exactly what raced: Spring Security's
   * {@code OnCommittedResponseWrapper} fires its response-committed callback the moment the written
   * count reaches that length, adding security headers from the async thread into a header map the
   * main thread was reading — an intermittent {@code ConcurrentModificationException} on precisely
   * these tests.
   */
  protected ResultActions streamPdf(MockHttpServletRequestBuilder request) throws Exception {
    return mockMvc.perform(request);
  }

  @DynamicPropertySource
  static void datasource(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", ORACLE::getJdbcUrl);
    registry.add("spring.datasource.username", ORACLE::getUsername);
    registry.add("spring.datasource.password", ORACLE::getPassword);
    registry.add("ilcr.datasource.enabled", () -> "true");
    // Migrations applied manually in the static block above; keep Boot's Flyway off.
    registry.add("spring.flyway.enabled", () -> "false");
  }
}
