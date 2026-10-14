package ca.bc.gov.nrs.ilcr.schedule11;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
 * Story 25.3 acceptance — {@code GET /api/v1/schedule11/biogeoclimatic-catalogue?q=} (AC6, BR-09,
 * slice S16). A read-only, global (no mill/year) type-ahead over {@code
 * THE.BIOGEOCLIMATIC_CATALOGUE}: a case-insensitive PREFIX match of {@code q} on the concatenated
 * zone+subzone+variant+phase label (the SAME concat the served location rows use), label-ordered
 * and capped. A blank/whitespace {@code q} returns {@code []}.
 *
 * <p>Security is ON for the whole class (as {@link Schedule11AuthorizationIT}) so the real {@code
 * oauth2ResourceServer} chain + {@code @PreAuthorize} run: the functional cases authenticate as
 * {@code ILCR_SUBMITTER} (which holds {@code VIEW_SCHEDULE}); the deny case sends no group and
 * expects 403. GET is a safe method — no CSRF token needed (unlike the sibling write ITs). Asserts
 * against the V20 (8801-8803) + V22 (8804-8807, shared 'SBS' prefix) + V23 (8901-8951, the 'ZZQ'
 * 51-row cap block) catalogue fixtures.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("GET /api/v1/schedule11/biogeoclimatic-catalogue — BEC type-ahead (Story 25.3)")
class Schedule11BiogeoCatalogueIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/schedule11/biogeoclimatic-catalogue";
  private static final String PROBLEM_JSON = "application/problem+json";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  // jwt() injects the Jwt directly; a mock JwtDecoder only satisfies chain construction (the real
  // FAM decoder wiring is the deferred auth story) — the established Boot-4 idiom.
  @MockitoBean private JwtDecoder jwtDecoder;

  private RequestPostProcessor jwtWithGroups(List<String> groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", groups))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("prefix hit -> 200 JSON list of {id,label}, label-ordered, matches only the prefix")
  void prefixHit_returnsOrderedOptions() throws Exception {
    // 'SBS' matches 8804/8805/8806 (in label order SBSdk < SBSmc2 < SBSwk1a); 8807 ('SBPSxc')
    // is the near-miss a prefix (not contains) match must exclude.
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("q", "SBS")
                .with(canonicalSubmitter())
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$", org.hamcrest.Matchers.hasSize(3)))
        .andExpect(jsonPath("$[*].id", contains(8804, 8805, 8806)))
        // label is the same zone+subzone+variant+phase concat as SilvicultureLocation.becLabel.
        .andExpect(jsonPath("$[*].label", contains("SBSdk", "SBSmc2", "SBSwk1a")));
  }

  @Test
  @DisplayName("case-insensitive prefix -> lowercase 'sbs' matches the same rows")
  void lowercasePrefix_matchesCaseInsensitively() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("q", "sbs")
                .with(canonicalSubmitter())
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[*].label", contains("SBSdk", "SBSmc2", "SBSwk1a")));
  }

  @Test
  @DisplayName("narrower prefix -> 'SBSm' resolves to the single SBSmc2 option")
  void narrowerPrefix_narrowsResult() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("q", "SBSm")
                .with(canonicalSubmitter())
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$", org.hamcrest.Matchers.hasSize(1)))
        .andExpect(jsonPath("$[0].id", is(8805)))
        .andExpect(jsonPath("$[0].label", is("SBSmc2")));
  }

  @Test
  @DisplayName("blank/whitespace q -> 200 empty list (legacy minQueryLength=1)")
  void blankTerm_returnsEmptyList() throws Exception {
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("q", "   ")
                .with(canonicalSubmitter())
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$", is(empty())));
  }

  @Test
  @DisplayName("absent q param -> 200 empty list")
  void absentTerm_returnsEmptyList() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(canonicalSubmitter()).accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$", is(empty())));
  }

  @Test
  @DisplayName("LIKE metacharacters match literally -> '%' and '_' are not wildcards")
  void likeMetacharacters_matchLiterally() throws Exception {
    // Unescaped, '%' would return the first 50 rows of the whole catalogue and 'SB_' would
    // match 'SBS…' via the any-character wildcard. Escaped (legacy String.startsWith parity),
    // neither matches any real label.
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("q", "%")
                .with(canonicalSubmitter())
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$", is(empty())));
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("q", "SB_")
                .with(canonicalSubmitter())
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$", is(empty())));
  }

  @Test
  @DisplayName("result cap -> 51 'ZZQ' fixture rows return exactly the first 50, label-ordered")
  void resultCap_boundsTypeAheadPayload() throws Exception {
    // V23 seeds ZZQz01..ZZQz51; FETCH FIRST 50 ROWS ONLY must drop the label-order tail (z51).
    mockMvc
        .perform(
            get(ENDPOINT)
                .param("q", "ZZQ")
                .with(canonicalSubmitter())
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$", org.hamcrest.Matchers.hasSize(50)))
        .andExpect(jsonPath("$[0].label", is("ZZQz01")))
        .andExpect(jsonPath("$[49].label", is("ZZQz50")));
  }

  @Test
  @DisplayName("no token -> 401 (resource-server chain, before @PreAuthorize)")
  void anonymous_returns401() throws Exception {
    mockMvc.perform(get(ENDPOINT).param("q", "SBS")).andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("no group (no VIEW_SCHEDULE) -> 403 ProblemDetail")
  void noPermission_returns403() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).param("q", "SBS").with(jwtWithGroups(List.of())))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON));
  }
}
