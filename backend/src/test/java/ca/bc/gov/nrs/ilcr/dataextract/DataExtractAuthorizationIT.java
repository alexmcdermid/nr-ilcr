package ca.bc.gov.nrs.ilcr.dataextract;

import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Authorization on the Data Extract endpoint (AD-7). Security ON, so the request travels the real
 * {@code oauth2ResourceServer} chain and {@code @PreAuthorize}.
 *
 * <p>The action is the extract's OWN capability, not the Generate Reports area's: legacy gated this
 * page on an {@code extractData} action derived from its view id ({@code
 * AuthorizationPhaseListener.java:145-161}), a different action from the {@code generateReports}
 * submenu gate at {@code menu.xhtml:38}. A submitter is denied even though they hold VIEW_SCHEDULE
 * — an extract spans every mill they did not select and was never theirs.
 *
 * <p>Note what an IT CANNOT prove here: ADMIN holds every action, so a role-based test cannot pin
 * WHICH action gates the endpoint, only that admins pass and submitters do not. The action name
 * itself is pinned by {@link DataExtractControllerAuthorizationTest}.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("POST /api/v1/reports/data-extract — authorization on GENERATE_DATA_EXTRACT (AD-7)")
class DataExtractAuthorizationIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/reports/data-extract";

  /** A fully valid selection, so a rejection can only be the authorization gate. */
  private static final String VALID_BODY =
      "{\"startYear\":\"2020\",\"endYear\":\"2021\",\"millIds\":[514],\"schedules\":[\"Schedule 1\"]}";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private ResultActions submitAs(RequestPostProcessor caller) throws Exception {
    return mockMvc.perform(
        post(ENDPOINT)
            .with(caller)
            .contentType(MediaType.APPLICATION_JSON)
            .content(VALID_BODY)
            .accept(MediaType.APPLICATION_JSON));
  }

  @Test
  @DisplayName("no token (anonymous) -> 401")
  void anonymous_returns401() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(VALID_BODY)
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> 403; holding VIEW_SCHEDULE is not enough for an extract")
  void submitter_returns403() throws Exception {
    submitAs(jwtWithGroups(List.of("ILCR_SUBMITTER"))).andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("the canonical submitter, associated to every seeded mill, is still 403")
  void associatedSubmitter_returns403() throws Exception {
    // Mill association is beside the point: this is not a mill-scoped endpoint but an ADMIN-only
    // one. A submitter who can reach every schedule still cannot extract.
    submitAs(canonicalSubmitter()).andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("no groups at all -> 403")
  void noGroups_returns403() throws Exception {
    submitAs(jwtWithGroups(List.of())).andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("ILCR_ADMIN passes the gate and receives the CSV attachment")
  void admin_passesTheGate() throws Exception {
    submitAs(jwtWithGroups(List.of("ILCR_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(content().contentType("application/csv;charset=UTF-8"))
        .andExpect(header().string("Content-Disposition", startsWith("attachment; filename=\"")));
  }
}
