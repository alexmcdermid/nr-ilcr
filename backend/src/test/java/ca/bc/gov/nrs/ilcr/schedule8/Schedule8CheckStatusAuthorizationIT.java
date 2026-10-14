package ca.bc.gov.nrs.ilcr.schedule8;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Acceptance test — authorization on VIEW_SCHEDULE (AD-7) for the Schedule 8 Check Status
 * endpoints. Security ON. Empty group → 403; {@code ILCR_SUBMITTER} passes (read-only, so VIEW is
 * sufficient).
 *
 * <p>Since #359 (group C) both endpoints require a body carrying the open panel. Each endpoint
 * covers empty groups, a foreign group and a mill-associated caller with no ILCR group (all 403),
 * and a submitter and an admin (2xx). The mill-associated-without-group case is the only one that
 * pins the {@code @PreAuthorize} gate itself; mirrors {@code Schedule4CheckStatusAuthorizationIT}.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("POST /api/v1/schedule8/check-status — authorization on VIEW_SCHEDULE (AD-7)")
class Schedule8CheckStatusAuthorizationIT extends AbstractOracleIT {

  private static final String ALL = "/api/v1/schedule8/check-status";
  private static final String PAGE = "/api/v1/schedule8/pages/8970/check-status";

  /**
   * The all-pages body: a REAL, partial page panel (Contact cleared). Its content is irrelevant to
   * authz, but posting it is what reaches the gate rather than a 400.
   */
  private static final String ALL_BODY =
      "{\"page\":{\"id\":8970,\"division\":\"North Div\",\"contact\":null,"
          + "\"phone\":\"2505551212\",\"tsaNumber\":\"TSA5\",\"tflNumber\":null,"
          + "\"supplyBlock\":\"B\",\"cuttingPermit\":null}}";

  /** The single-page body: a REAL, partial sample panel (a new sample, Cut Block blank). */
  private static final String PAGE_BODY =
      "{\"sample\":{\"id\":null,\"contractId\":\"CAUTH\",\"cutBlock\":null,"
          + "\"groundBasePct\":100,\"coniferousVolume\":100,\"deciduousVolume\":0,"
          + "\"originalRate\":12.5}}";

  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  /**
   * The canonical submitter's GUID, which passes Story 5.7 mill-scope for the seeded mill, but no
   * ILCR group: only the {@code @PreAuthorize} gate can refuse it. The empty-groups and
   * foreign-group cases are also refused by mill-scope (no associated GUID), which raises the same
   * 403 body — so on their own they would stay green without the VIEW_SCHEDULE gate.
   */
  private static RequestPostProcessor millAssociatedWithoutGroup() {
    return jwt()
        .jwt(
            j ->
                j.claim("idir_user_guid", CANONICAL_SUBMITTER_GUID)
                    .claim("identity_provider", "azureidir")
                    .claim("client_roles", List.of()))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  private static MockHttpServletRequestBuilder checkAll() {
    return post(ALL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(ALL_BODY)
        .param("millId", "600")
        .param("year", "2021")
        .with(csrf());
  }

  private static MockHttpServletRequestBuilder checkPage() {
    return post(PAGE)
        .contentType(MediaType.APPLICATION_JSON)
        .content(PAGE_BODY)
        .param("millId", "600")
        .param("year", "2021")
        .with(csrf());
  }

  @Test
  @DisplayName("no VIEW_SCHEDULE -> POST check-status 403")
  void noPermission_returns403() throws Exception {
    mockMvc
        .perform(checkAll().with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("foreign group (no ILCR_ suffix) -> POST check-status 403")
  void foreignGroup_returns403() throws Exception {
    mockMvc
        .perform(checkAll().with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName(
      "mill-associated GUID but no ILCR group -> POST check-status 403 from the gate itself")
  void millAssociatedWithoutGroup_returns403() throws Exception {
    mockMvc
        .perform(checkAll().with(millAssociatedWithoutGroup()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> POST check-status passes authz (not 403)")
  void submitter_passesAuthorization() throws Exception {
    mockMvc.perform(checkAll().with(canonicalSubmitter())).andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("ILCR_ADMIN -> POST check-status passes authz (2xx)")
  void admin_passesAuthorization() throws Exception {
    mockMvc
        .perform(checkAll().with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("no VIEW_SCHEDULE -> POST single-page check-status 403")
  void page_noPermission_returns403() throws Exception {
    mockMvc
        .perform(checkPage().with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("foreign group (no ILCR_ suffix) -> POST single-page check-status 403")
  void page_foreignGroup_returns403() throws Exception {
    mockMvc
        .perform(checkPage().with(jwtWithGroups(List.of("SOME_OTHER_APP_ADMIN"))))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName(
      "mill-associated GUID but no ILCR group -> POST single-page check-status 403 from the gate")
  void page_millAssociatedWithoutGroup_returns403() throws Exception {
    mockMvc
        .perform(checkPage().with(millAssociatedWithoutGroup()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER -> POST single-page check-status passes authz (not 403)")
  void page_submitter_passesAuthorization() throws Exception {
    mockMvc.perform(checkPage().with(canonicalSubmitter())).andExpect(status().is2xxSuccessful());
  }

  @Test
  @DisplayName("ILCR_ADMIN -> POST single-page check-status passes authz (2xx)")
  void page_admin_passesAuthorization() throws Exception {
    mockMvc
        .perform(checkPage().with(jwtWithGroups(List.of("ILCR_ADMIN"))))
        .andExpect(status().is2xxSuccessful());
  }
}
