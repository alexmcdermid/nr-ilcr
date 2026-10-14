package ca.bc.gov.nrs.ilcr.schedule3;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test for authorization on the Schedule 3 sub-resources (Story 4.4, AD-7): Other
 * Acceptable Costs and Included Unacceptable Costs. Security ON, authorities derived through the
 * production {@link FamJwtAuthenticationConverter}: GET requires VIEW_SCHEDULE (denied without an
 * ILCR group, allowed for ILCR_SUBMITTER); POST/PUT/DELETE require EDIT_SCHEDULE and are denied 403
 * before any persistence. The behavior itself is proven security-off by {@link
 * Schedule3OtherAcceptableIT} / {@link Schedule3UnacceptableIT}.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("Schedule 3 sub-resources — authorization (AD-7, Story 4.4)")
class Schedule3SubPageAuthorizationIT extends AbstractOracleIT {

  // Mill 574 has a category-3 summary (V19 read fixtures), so an authorized GET reaches 2xx.
  private static final String MILL = "574";
  private static final String OTHER_ACCEPTABLE = "/api/v1/schedule3/other-acceptable-costs";
  private static final String UNACCEPTABLE = "/api/v1/schedule3/included-unacceptable-costs";
  private static final String OA_BODY =
      """
      { "description": "Consulting", "total": 100, "pop": 50 }
      """;
  private static final String UNACCEPT_BODY =
      """
      { "description": "Penalty", "total": 100 }
      """;
  // Batch-save (collection PUT) bodies for the new sub-page save endpoints.
  private static final String OA_SAVE_BODY =
      """
      { "rows": [ { "id": 1, "description": "Consulting", "total": 100, "pop": 50 } ] }
      """;
  private static final String UNACCEPT_SAVE_BODY =
      """
      { "rows": [ { "id": 1, "description": "Penalty", "total": 100 } ] }
      """;
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  // ---- Other Acceptable Costs -------------------------------------------------------------------

  @Test
  @DisplayName("Other Acceptable GET without VIEW_SCHEDULE -> 403")
  void otherAcceptableGet_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            get(OTHER_ACCEPTABLE)
                .param("millId", MILL)
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("Other Acceptable GET with ILCR_SUBMITTER -> passes authz (2xx)")
  void otherAcceptableGet_submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            get(OTHER_ACCEPTABLE)
                .param("millId", MILL)
                .param("year", "2021")
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("Other Acceptable POST without EDIT_SCHEDULE -> 403")
  void otherAcceptablePost_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            post(OTHER_ACCEPTABLE)
                .param("millId", MILL)
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(OA_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("Other Acceptable PUT without EDIT_SCHEDULE -> 403")
  void otherAcceptablePut_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(OTHER_ACCEPTABLE + "/1")
                .param("millId", MILL)
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(OA_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("Other Acceptable DELETE without EDIT_SCHEDULE -> 403")
  void otherAcceptableDelete_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            delete(OTHER_ACCEPTABLE + "/1")
                .param("millId", MILL)
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("Other Acceptable batch PUT (save) without EDIT_SCHEDULE -> 403")
  void otherAcceptableBatchPut_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(OTHER_ACCEPTABLE)
                .param("millId", MILL)
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(OA_SAVE_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  // ---- Included Unacceptable Costs --------------------------------------------------------------

  @Test
  @DisplayName("Unacceptable GET without VIEW_SCHEDULE -> 403")
  void unacceptableGet_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            get(UNACCEPTABLE)
                .param("millId", MILL)
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("Unacceptable GET with ILCR_SUBMITTER -> passes authz (2xx)")
  void unacceptableGet_submitter_passesAuthorization() throws Exception {
    mockMvc
        .perform(
            get(UNACCEPTABLE)
                .param("millId", MILL)
                .param("year", "2021")
                .with(canonicalSubmitter()))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("Unacceptable POST without EDIT_SCHEDULE -> 403")
  void unacceptablePost_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            post(UNACCEPTABLE)
                .param("millId", MILL)
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(UNACCEPT_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("Unacceptable PUT without EDIT_SCHEDULE -> 403")
  void unacceptablePut_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(UNACCEPTABLE + "/1")
                .param("millId", MILL)
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(UNACCEPT_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("Unacceptable DELETE without EDIT_SCHEDULE -> 403")
  void unacceptableDelete_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            delete(UNACCEPTABLE + "/1")
                .param("millId", MILL)
                .param("year", "2021")
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("Unacceptable batch PUT (save) without EDIT_SCHEDULE -> 403")
  void unacceptableBatchPut_noPermission_returns403() throws Exception {
    mockMvc
        .perform(
            put(UNACCEPTABLE)
                .param("millId", MILL)
                .param("year", "2021")
                .contentType(MediaType.APPLICATION_JSON)
                .content(UNACCEPT_SAVE_BODY)
                .with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }
}
