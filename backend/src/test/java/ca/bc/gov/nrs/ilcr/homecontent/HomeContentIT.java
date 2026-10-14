package ca.bc.gov.nrs.ilcr.homecontent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
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

/**
 * Acceptance test — Story 24.2 (UC-CNT-001) Content Editing, security ON. Save/list are ADMIN-only
 * ({@code EDIT_HOME_CONTENT}); a submitter is 403 (S13). {@code /mine} is authenticated-only and
 * returns the caller-role message (Licensee vs Administrator). Proves the atomic save, the legacy
 * transform, per-field FLD-001, and the audit user stamp against the real {@code THE.ILCR_ROLE}.
 */
@TestPropertySource(properties = "ilcr.security.enabled=true")
@DisplayName("/api/v1/home-content — Content Editing (Story 24.2)")
class HomeContentIT extends AbstractOracleIT {

  private static final String ENDPOINT = "/api/v1/home-content";
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
  @DisplayName("admin lists all three role messages")
  void admin_listsAllRoles() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(groups("ILCR_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(3))
        .andExpect(jsonPath("$[*].role", hasItem("LICENSEE")))
        .andExpect(jsonPath("$[*].role", hasItem("ADMIN")));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER is denied save — 403 (S13)")
  void submitter_saveForbidden() throws Exception {
    String body =
        """
        {"licensee":"<p>L</p>","auditor":"<p>A</p>","administrator":"<p>Adm</p>"}""";
    mockMvc
        .perform(
            put(ENDPOINT)
                .with(groups("ILCR_SUBMITTER"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("ILCR_SUBMITTER is denied the admin list — 403 (S13)")
  void submitter_listForbidden() throws Exception {
    mockMvc
        .perform(get(ENDPOINT).with(groups("ILCR_SUBMITTER")))
        .andExpect(status().isForbidden())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
  }

  @Test
  @DisplayName("no ILCR group is denied the admin list — 403")
  void noGroup_listForbidden() throws Exception {
    mockMvc.perform(get(ENDPOINT).with(groups())).andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("a blank editor is rejected 400 (FLD-001) and nothing is saved")
  void blankEditorRejected() throws Exception {
    String body =
        """
        {"licensee":"<p></p>","auditor":"<p>A</p>","administrator":"<p>Adm</p>"}""";
    mockMvc
        .perform(
            put(ENDPOINT)
                .with(groups("ILCR_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
        .andExpect(jsonPath("$.detail", containsString("Licensee Welcome Message")));
  }

  @Test
  @DisplayName("a missing role row is inserted and its audit fields are initialized")
  void missingRoleRowIsRepaired() throws Exception {
    jdbc.update(
        "DELETE FROM THE.ILCR_ROLE WHERE ILCR_ROLE_NAME = :role",
        new MapSqlParameterSource("role", "AUDITOR"));

    String body =
        """
        {"licensee":"<p>Repair L</p>","auditor":"<p>Repair A</p>","administrator":"<p>Repair Adm</p>"}""";
    mockMvc
        .perform(
            put(ENDPOINT)
                .with(groups("ILCR_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.entries[*].role", hasItem("AUDITOR")));

    Integer revision =
        jdbc.queryForObject(
            "SELECT REVISION_COUNT FROM THE.ILCR_ROLE WHERE ILCR_ROLE_NAME = :role",
            new MapSqlParameterSource("role", "AUDITOR"),
            Integer.class);
    String entryUser =
        jdbc.queryForObject(
            "SELECT ENTRY_USERID FROM THE.ILCR_ROLE WHERE ILCR_ROLE_NAME = :role",
            new MapSqlParameterSource("role", "AUDITOR"),
            String.class);
    assertThat(revision).isZero();
    assertThat(entryUser).isNotBlank();
  }

  @Test
  @DisplayName("a late save validation failure leaves earlier role updates unchanged")
  void lateValidationFailureIsAtomic() throws Exception {
    String beforeLicensee =
        jdbc.queryForObject(
            "SELECT MESSAGE_TEXT FROM THE.ILCR_ROLE WHERE ILCR_ROLE_NAME = :role",
            new MapSqlParameterSource("role", "LICENSEE"),
            String.class);
    String beforeAuditor =
        jdbc.queryForObject(
            "SELECT MESSAGE_TEXT FROM THE.ILCR_ROLE WHERE ILCR_ROLE_NAME = :role",
            new MapSqlParameterSource("role", "AUDITOR"),
            String.class);
    String body =
        "{\"licensee\":\"<p>Would roll back</p>\",\"auditor\":\"<p>Would roll back</p>\",\"administrator\":\""
            + "x".repeat(4100)
            + "\"}";

    mockMvc
        .perform(
            put(ENDPOINT)
                .with(groups("ILCR_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isBadRequest());

    assertThat(
            jdbc.queryForObject(
                "SELECT MESSAGE_TEXT FROM THE.ILCR_ROLE WHERE ILCR_ROLE_NAME = :role",
                new MapSqlParameterSource("role", "LICENSEE"),
                String.class))
        .isEqualTo(beforeLicensee);
    assertThat(
            jdbc.queryForObject(
                "SELECT MESSAGE_TEXT FROM THE.ILCR_ROLE WHERE ILCR_ROLE_NAME = :role",
                new MapSqlParameterSource("role", "AUDITOR"),
                String.class))
        .isEqualTo(beforeAuditor);
  }

  @Test
  @DisplayName(
      "admin saves all three atomically (transform + audit); /mine reflects the caller role")
  void admin_savesAndMineReflectsRole() throws Exception {
    // The admin message carries a tab to prove the legacy save-transform (tab -> two spaces).
    String body =
        """
        {"licensee":"<p>LIC</p>","auditor":"<p>AUD</p>","administrator":"<p>AD\\tM</p>"}""";
    mockMvc
        .perform(
            put(ENDPOINT)
                .with(groups("ILCR_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Data saved successfully"));

    // /mine returns the caller-role message: admin -> Administrator (transformed), submitter ->
    // Licensee.
    mockMvc
        .perform(get(ENDPOINT + "/mine").with(groups("ILCR_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.role").value("ADMIN"))
        .andExpect(jsonPath("$.messageText").value("<p>AD  M</p>"));
    mockMvc
        .perform(get(ENDPOINT + "/mine").with(groups("ILCR_SUBMITTER")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.role").value("LICENSEE"))
        .andExpect(jsonPath("$.messageText").value("<p>LIC</p>"));

    // Audit user stamped from the principal, not the seed's 'SEED'.
    String updatedBy =
        jdbc.queryForObject(
            "SELECT UPDATE_USERID FROM THE.ILCR_ROLE WHERE ILCR_ROLE_NAME = 'ADMIN'",
            new MapSqlParameterSource(),
            String.class);
    assertThat(updatedBy).isNotNull().isNotEqualTo("SEED");
  }
}
