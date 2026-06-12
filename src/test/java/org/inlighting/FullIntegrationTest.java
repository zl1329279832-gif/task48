package org.inlighting;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.inlighting.database.DataSource;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = WebApplication.class)
@AutoConfigureMockMvc
public class FullIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private ObjectMapper objectMapper = new ObjectMapper();

    @Before
    public void resetData() {
        DataSource.resetData();
    }

    // ==================== Helper Methods ====================

    private String loginAndGetToken(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/login")
                .param("username", username)
                .param("password", password))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andReturn();

        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        return json.get("data").asText();
    }

    // ==================== Original Endpoint Tests ====================

    @Test
    public void testArticleAsGuest() throws Exception {
        mockMvc.perform(get("/article"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("You are guest"));
    }

    @Test
    public void testArticleAuthenticated() throws Exception {
        String token = loginAndGetToken("smith", "smith123");
        mockMvc.perform(get("/article").header("Authorization", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("You are already logged in"));
    }

    @Test
    public void testRequireAuthWithValidToken() throws Exception {
        String token = loginAndGetToken("smith", "smith123");
        mockMvc.perform(get("/require_auth").header("Authorization", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("You are authenticated"));
    }

    @Test
    public void testRequireRoleAsAdmin() throws Exception {
        String token = loginAndGetToken("danny", "danny123");
        mockMvc.perform(get("/require_role").header("Authorization", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("You are visiting require_role"));
    }

    @Test
    public void testRequirePermissionAsAdmin() throws Exception {
        String token = loginAndGetToken("danny", "danny123");
        mockMvc.perform(get("/require_permission").header("Authorization", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("You are visiting permission require edit,view"));
    }

    // ==================== 401 Tests ====================

    @Test
    public void testNoTokenOnProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(401));
    }

    @Test
    public void testNoTokenOnRequireAuth() throws Exception {
        mockMvc.perform(get("/require_auth"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(401));
    }

    @Test
    public void testInvalidTokenOnArticle() throws Exception {
        // Invalid token: filter catches auth failure and redirects to /401
        mockMvc.perform(get("/article").header("Authorization", "invalid.token.here"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    public void testInvalidTokenOnProtectedEndpoint() throws Exception {
        // Invalid token on protected endpoint: filter redirects to /401
        MvcResult result = mockMvc.perform(get("/me").header("Authorization", "invalid.token.here"))
                .andReturn();
        // Either redirected to /401 (302) or the annotation catches it (401)
        int status = result.getResponse().getStatus();
        assert status == 302 || status == 401 : "Expected 302 or 401, got " + status;
    }

    // ==================== 403 Tests ====================

    @Test
    public void testForbiddenRoleAccess() throws Exception {
        String token = loginAndGetToken("smith", "smith123");
        mockMvc.perform(get("/require_role").header("Authorization", token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(403));
    }

    @Test
    public void testForbiddenPermissionAccess() throws Exception {
        String token = loginAndGetToken("smith", "smith123");
        mockMvc.perform(get("/require_permission").header("Authorization", token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(403));
    }

    // ==================== /me Endpoint Tests ====================

    @Test
    public void testMeAsSmith() throws Exception {
        String token = loginAndGetToken("smith", "smith123");
        mockMvc.perform(get("/me").header("Authorization", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.data.username").value("smith"))
                .andExpect(jsonPath("$.data.role").value("user"))
                .andExpect(jsonPath("$.data.permissions[0]").value("view"))
                .andExpect(jsonPath("$.data.tokenExpiresAt").isNotEmpty());
    }

    @Test
    public void testMeAsDanny() throws Exception {
        String token = loginAndGetToken("danny", "danny123");
        mockMvc.perform(get("/me").header("Authorization", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("danny"))
                .andExpect(jsonPath("$.data.role").value("admin"))
                .andExpect(jsonPath("$.data.permissions", hasItems("view", "edit")))
                .andExpect(jsonPath("$.data.tokenExpiresAt").isNotEmpty());
    }

    // ==================== /me/permissions Endpoint Tests ====================

    @Test
    public void testMePermissionsAsUser() throws Exception {
        String token = loginAndGetToken("smith", "smith123");
        MvcResult result = mockMvc.perform(get("/me/permissions").header("Authorization", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andReturn();

        JsonNode data = objectMapper.readTree(result.getResponse().getContentAsString()).get("data");
        // smith (role=user, permission=view) should NOT have access to require_role or require_permission
        boolean requireRoleAccessible = false;
        boolean requirePermissionAccessible = false;
        for (JsonNode ep : data) {
            if ("/require_role".equals(ep.get("path").asText())) {
                requireRoleAccessible = ep.get("accessible").asBoolean();
            }
            if ("/require_permission".equals(ep.get("path").asText())) {
                requirePermissionAccessible = ep.get("accessible").asBoolean();
            }
        }
        assert !requireRoleAccessible : "/require_role should not be accessible for smith";
        assert !requirePermissionAccessible : "/require_permission should not be accessible for smith";
    }

    @Test
    public void testMePermissionsAsAdmin() throws Exception {
        String token = loginAndGetToken("danny", "danny123");
        MvcResult result = mockMvc.perform(get("/me/permissions").header("Authorization", token))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode data = objectMapper.readTree(result.getResponse().getContentAsString()).get("data");
        // danny (role=admin, permission=view,edit) should have access to everything
        for (JsonNode ep : data) {
            assert ep.get("accessible").asBoolean() :
                    ep.get("path").asText() + " should be accessible for danny";
        }
    }

    // ==================== Admin Mutation Tests ====================

    @Test
    public void testAdminUpdateRole() throws Exception {
        String adminToken = loginAndGetToken("danny", "danny123");
        String smithToken = loginAndGetToken("smith", "smith123");

        // smith cannot access /require_role initially
        mockMvc.perform(get("/require_role").header("Authorization", smithToken))
                .andExpect(status().isForbidden());

        // admin changes smith's role to admin
        mockMvc.perform(put("/admin/user/smith/role")
                .header("Authorization", adminToken)
                .param("role", "admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Role updated"));

        // smith can now access /require_role
        mockMvc.perform(get("/require_role").header("Authorization", smithToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("You are visiting require_role"));

        // /me reflects the change
        mockMvc.perform(get("/me").header("Authorization", smithToken))
                .andExpect(jsonPath("$.data.role").value("admin"));
    }

    @Test
    public void testAdminUpdatePermission() throws Exception {
        String adminToken = loginAndGetToken("danny", "danny123");
        String smithToken = loginAndGetToken("smith", "smith123");

        // smith cannot access /require_permission initially (only has 'view')
        mockMvc.perform(get("/require_permission").header("Authorization", smithToken))
                .andExpect(status().isForbidden());

        // admin grants smith 'view,edit' permissions
        mockMvc.perform(put("/admin/user/smith/permission")
                .header("Authorization", adminToken)
                .param("permission", "view,edit"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Permission updated"));

        // smith can now access /require_permission
        mockMvc.perform(get("/require_permission").header("Authorization", smithToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("You are visiting permission require edit,view"));

        // /me reflects the change
        mockMvc.perform(get("/me").header("Authorization", smithToken))
                .andExpect(jsonPath("$.data.permissions", hasItems("view", "edit")));
    }

    @Test
    public void testNonAdminCannotMutate() throws Exception {
        String smithToken = loginAndGetToken("smith", "smith123");

        // smith (role=user) cannot access admin endpoints
        mockMvc.perform(put("/admin/user/danny/role")
                .header("Authorization", smithToken)
                .param("role", "user"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(403));
    }

    @Test
    public void testAdminUpdateNonExistentUser() throws Exception {
        String adminToken = loginAndGetToken("danny", "danny123");

        mockMvc.perform(put("/admin/user/nobody/role")
                .header("Authorization", adminToken)
                .param("role", "admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(404))
                .andExpect(jsonPath("$.msg").value("User not found"));
    }

    // ==================== Permission Change Reflects in /me/permissions ====================

    @Test
    public void testPermissionChangeReflectsInMePermissions() throws Exception {
        String adminToken = loginAndGetToken("danny", "danny123");
        String smithToken = loginAndGetToken("smith", "smith123");

        // Before: smith sees /require_permission as not accessible
        MvcResult before = mockMvc.perform(get("/me/permissions").header("Authorization", smithToken))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode dataBefore = objectMapper.readTree(before.getResponse().getContentAsString()).get("data");
        for (JsonNode ep : dataBefore) {
            if ("/require_permission".equals(ep.get("path").asText())) {
                assert !ep.get("accessible").asBoolean();
            }
        }

        // Admin grants edit permission
        mockMvc.perform(put("/admin/user/smith/permission")
                .header("Authorization", adminToken)
                .param("permission", "view,edit"))
                .andExpect(status().isOk());

        // After: smith sees /require_permission as accessible
        MvcResult after = mockMvc.perform(get("/me/permissions").header("Authorization", smithToken))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode dataAfter = objectMapper.readTree(after.getResponse().getContentAsString()).get("data");
        for (JsonNode ep : dataAfter) {
            if ("/require_permission".equals(ep.get("path").asText())) {
                assert ep.get("accessible").asBoolean();
            }
        }
    }

    // ==================== Login Failure Tests ====================

    @Test
    public void testLoginWrongPassword() throws Exception {
        mockMvc.perform(post("/login")
                .param("username", "smith")
                .param("password", "wrongpassword"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(401));
    }
}
