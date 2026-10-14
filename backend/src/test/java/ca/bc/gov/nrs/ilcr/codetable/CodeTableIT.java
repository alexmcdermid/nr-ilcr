package ca.bc.gov.nrs.ilcr.codetable;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ca.bc.gov.nrs.ilcr.security.FamJwtAuthenticationConverter;
import ca.bc.gov.nrs.ilcr.support.AbstractOracleIT;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;

/**
 * Acceptance test — Story 24.3 (UC-CODE-001) Table Maintenance, security ON. Exercises the real
 * cognito:groups → role → action path: {@code MAINTAIN_CODE_TABLES} is ADMIN-only, so an {@code
 * ILCR_SUBMITTER} is denied 403 (S13) — the opposite of the schedule endpoints. Functional
 * read/write is driven with an admin JWT against the {@code ILCR_UNIT_CODE} seed (V20260812).
 */
@Transactional
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("/api/v1/code-tables — Table Maintenance (admin-gated, Story 24.3)")
class CodeTableIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/code-tables";
  private static final String UNIT_ENTRIES = ENDPOINT + "/UNIT_CODE/entries";
  private static final String CONTRACTUAL_ENTRIES = ENDPOINT + "/CONTRACTUAL_ITEM_CODE/entries";
  private static final FamJwtAuthenticationConverter CONVERTER =
      new FamJwtAuthenticationConverter();

  @MockitoBean private JwtDecoder jwtDecoder;

  @Autowired private NamedParameterJdbcTemplate jdbc;

  private RequestPostProcessor groups(String... groups) {
    return jwt()
        .jwt(j -> j.claim("identity_provider", "azureidir").claim("client_roles", List.of(groups)))
        .authorities(j -> CONVERTER.convert(j).getAuthorities());
  }

  @Test
  @DisplayName("admin lists all 19 legacy maintainable tables")
  void admin_listsTables() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(groups("ILCR_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(19))
        .andExpect(jsonPath("$[*].key", hasItem("UNIT_CODE")))
        .andExpect(jsonPath("$[*].key", hasItem("CONTRACTUAL_ITEM_CODE")));
  }

  @Test
  @DisplayName("admin reads a table's entries")
  void admin_readsEntries() throws Exception {
    mockMvc
        .perform(get(UNIT_ENTRIES).with(groups("ILCR_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[*].code", hasItem("M3")));
  }

  @Test
  @DisplayName("admin adds a new entry — 200 INSERTED, verbatim success, reloaded grid")
  void admin_addsEntry() throws Exception {
    String body =
        """
        {"code":"IT1","description":"Integration Unit","effectiveDate":"2020-01-01",\
        "expiryDate":"2030-12-31"}""";
    mockMvc
        .perform(
            put(UNIT_ENTRIES)
                .with(groups("ILCR_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.outcome").value("INSERTED"))
        .andExpect(jsonPath("$.message").value("Data saved successfully"))
        .andExpect(jsonPath("$.entries[*].code", hasItem("IT1")));
  }

  @Test
  @DisplayName("admin adds a Contractual Item Code through the Schedule 9 cost-item path")
  void admin_addsContractualItem() throws Exception {
    Integer sequenceValue =
        jdbc.queryForObject(
            "SELECT THE.ILCR_REPORT_COST_ITEM_SEQ.NEXTVAL FROM DUAL",
            new MapSqlParameterSource(),
            Integer.class);
    String body =
        """
        {"code":"","description":"Integration contractual item",\
        "effectiveDate":"2020-01-01","expiryDate":"2030-12-31"}""";
    mockMvc
        .perform(
            put(CONTRACTUAL_ENTRIES)
                .with(groups("ILCR_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.outcome").value("INSERTED"))
        .andExpect(jsonPath("$.entries[*].description", hasItem("Integration contractual item")))
        .andExpect(jsonPath("$.entries[*].code", hasItem(String.valueOf(sequenceValue + 1))));
  }

  @Test
  @DisplayName("expiry before effective is rejected 400 and nothing is saved (FLD-005)")
  void invalidDateRange_is400() throws Exception {
    String body =
        """
        {"code":"IT2","description":"Bad Dates","effectiveDate":"2030-01-01",\
        "expiryDate":"2020-01-01"}""";
    mockMvc
        .perform(
            put(UNIT_ENTRIES)
                .with(groups("ILCR_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
        .andExpect(
            jsonPath("$.detail")
                .value("Expiry Date must be greater than or equal to Effective Date."));
    // Not persisted.
    mockMvc
        .perform(get(UNIT_ENTRIES).with(groups("ILCR_ADMIN")))
        .andExpect(jsonPath("$[*].code", not(hasItem("IT2"))));
  }

  @Test
  @DisplayName("blank generic code is rejected 400 problem+json by service validation")
  void blankCode_is400FromServiceValidation() throws Exception {
    // Blank code is valid only for Contractual Item Codes, where the server allocates the legacy
    // cost-item identifier. Generic tables retain the service-layer code-required rule.
    String body =
        """
        {"code":"","description":"Blank code","effectiveDate":"2020-01-01"}""";
    mockMvc
        .perform(
            put(UNIT_ENTRIES)
                .with(groups("ILCR_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
        .andExpect(jsonPath("$.title").value("Bad Request"))
        .andExpect(jsonPath("$.detail").value("Code: Value is required."));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER is denied write — 403 (S13, admin-only action)")
  void submitter_isForbidden() throws Exception {
    String body =
        """
        {"code":"IT3","description":"Nope","effectiveDate":"2020-01-01","expiryDate":"2030-12-31"}""";
    mockMvc
        .perform(
            put(UNIT_ENTRIES)
                .with(groups("ILCR_SUBMITTER"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no ILCR group is denied read — 403")
  void noGroup_isForbidden() throws Exception {
    mockMvc.perform(get(ENDPOINT).with(groups())).andExpect(status().isForbidden());
  }
}
