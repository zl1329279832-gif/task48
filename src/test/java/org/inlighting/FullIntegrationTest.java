package org.inlighting;

import org.inlighting.database.DataSource;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Map;

import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class FullIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Before
    public void setUp() {
        DataSource.resetData();
        // 使用 Apache HttpClient 代替默认的 SimpleClientHttpRequestFactory，
        // 避免 Java HttpURLConnection 对 401 响应的自动认证重试问题
        restTemplate.getRestTemplate().setRequestFactory(
                new HttpComponentsClientHttpRequestFactory());
    }

    // ========== Helper ==========

    private String login(String username, String password) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("username", username);
        params.add("password", password);
        ResponseEntity<Map> resp = restTemplate.postForEntity("/login", params, Map.class);
        if (resp.getStatusCodeValue() == 200 && resp.getBody() != null) {
            Object data = resp.getBody().get("data");
            return data != null ? data.toString() : null;
        }
        return null;
    }

    private HttpHeaders authHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", token);
        return headers;
    }

    @SuppressWarnings("unchecked")
    private <T> ResponseEntity<Map> get(String path, String token) {
        HttpEntity<T> entity = new HttpEntity<>(token != null ? authHeaders(token) : new HttpHeaders());
        return restTemplate.exchange(path, HttpMethod.GET, entity, Map.class);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map> put(String path, String token, MultiValueMap<String, String> params) {
        HttpHeaders headers = token != null ? authHeaders(token) : new HttpHeaders();
        if (params != null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);
        return restTemplate.exchange(path, HttpMethod.PUT, entity, Map.class);
    }

    // ========== Article Tests ==========

    @Test
    public void testArticleAsGuest() {
        ResponseEntity<Map> resp = get("/article", null);
        assertEquals(200, resp.getStatusCodeValue());
        assertEquals("You are guest", resp.getBody().get("msg"));
    }

    @Test
    public void testArticleAuthenticated() {
        String token = login("smith", "smith123");
        assertNotNull(token);
        ResponseEntity<Map> resp = get("/article", token);
        assertEquals(200, resp.getStatusCodeValue());
        assertEquals("You are already logged in", resp.getBody().get("msg"));
    }

    // ========== Require Auth Tests ==========

    @Test
    public void testRequireAuthWithValidToken() {
        String token = login("smith", "smith123");
        ResponseEntity<Map> resp = get("/require_auth", token);
        assertEquals(200, resp.getStatusCodeValue());
        assertEquals("You are authenticated", resp.getBody().get("msg"));
    }

    @Test
    public void testNoTokenOnRequireAuth() {
        ResponseEntity<Map> resp = get("/require_auth", null);
        assertEquals(401, resp.getStatusCodeValue());
    }

    @Test
    public void testNoTokenOnProtectedEndpoint() {
        ResponseEntity<Map> resp = get("/require_role", null);
        assertEquals(401, resp.getStatusCodeValue());
    }

    // ========== Invalid Token Tests ==========

    @Test
    public void testInvalidTokenOnArticle() {
        ResponseEntity<Map> resp = get("/article", "invalid-token-xxx");
        assertEquals(200, resp.getStatusCodeValue());
        assertEquals("You are guest", resp.getBody().get("msg"));
    }

    @Test
    public void testInvalidTokenOnProtectedEndpoint() {
        ResponseEntity<Map> resp = get("/require_auth", "invalid-token-xxx");
        assertEquals(401, resp.getStatusCodeValue());
    }

    // ========== Require Role Tests ==========

    @Test
    public void testRequireRoleAsAdmin() {
        String token = login("danny", "danny123");
        ResponseEntity<Map> resp = get("/require_role", token);
        assertEquals(200, resp.getStatusCodeValue());
    }

    @Test
    public void testForbiddenRoleAccess() {
        String token = login("smith", "smith123");
        ResponseEntity<Map> resp = get("/require_role", token);
        assertEquals(403, resp.getStatusCodeValue());
    }

    // ========== Require Permission Tests ==========

    @Test
    public void testRequirePermissionAsAdmin() {
        String token = login("danny", "danny123");
        ResponseEntity<Map> resp = get("/require_permission", token);
        assertEquals(200, resp.getStatusCodeValue());
    }

    @Test
    public void testForbiddenPermissionAccess() {
        String token = login("smith", "smith123");
        ResponseEntity<Map> resp = get("/require_permission", token);
        assertEquals(403, resp.getStatusCodeValue());
    }

    // ========== /me Tests ==========

    @Test
    public void testMeAsSmith() {
        String token = login("smith", "smith123");
        ResponseEntity<Map> resp = get("/me", token);
        assertEquals(200, resp.getStatusCodeValue());
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) resp.getBody().get("data");
        assertEquals("smith", data.get("username"));
        assertEquals("user", data.get("role"));
        assertNotNull(data.get("permissions"));
        assertNotNull(data.get("tokenExpireTime"));
    }

    @Test
    public void testMeAsDanny() {
        String token = login("danny", "danny123");
        ResponseEntity<Map> resp = get("/me", token);
        assertEquals(200, resp.getStatusCodeValue());
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) resp.getBody().get("data");
        assertEquals("danny", data.get("username"));
        assertEquals("admin", data.get("role"));
    }

    // ========== /me/permissions Tests ==========

    @Test
    public void testMePermissionsAsUser() {
        String token = login("smith", "smith123");
        ResponseEntity<Map> resp = get("/me/permissions", token);
        assertEquals(200, resp.getStatusCodeValue());
        // smith only has "view" permission, so /require_permission should NOT be accessible
        String body = resp.getBody().toString();
        assertTrue(body.contains("/require_permission"));
        // Find the require_permission entry and check accessible is false
        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> endpoints =
                (java.util.List<Map<String, Object>>) resp.getBody().get("data");
        boolean found = false;
        for (Map<String, Object> ep : endpoints) {
            if ("/require_permission".equals(ep.get("path"))) {
                assertEquals(false, ep.get("accessible"));
                found = true;
            }
        }
        assertTrue("Should find /require_permission endpoint", found);
    }

    @Test
    public void testMePermissionsAsAdmin() {
        String token = login("danny", "danny123");
        ResponseEntity<Map> resp = get("/me/permissions", token);
        assertEquals(200, resp.getStatusCodeValue());
        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> endpoints =
                (java.util.List<Map<String, Object>>) resp.getBody().get("data");
        boolean found = false;
        for (Map<String, Object> ep : endpoints) {
            if ("/require_permission".equals(ep.get("path"))) {
                assertEquals(true, ep.get("accessible"));
                found = true;
            }
        }
        assertTrue("Should find /require_permission endpoint", found);
    }

    // ========== Admin Update Tests ==========

    @Test
    public void testAdminUpdateRole() {
        String adminToken = login("danny", "danny123");

        // Update smith's role to admin
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("role", "admin");
        ResponseEntity<Map> updateResp = put("/admin/user/smith/role", adminToken, params);
        assertEquals(200, updateResp.getStatusCodeValue());
        assertEquals("Role updated", updateResp.getBody().get("msg"));

        // Smith should now be able to access /require_role
        String smithToken = login("smith", "smith123");
        ResponseEntity<Map> roleResp = get("/require_role", smithToken);
        assertEquals(200, roleResp.getStatusCodeValue());

        // /me should show updated role
        ResponseEntity<Map> meResp = get("/me", smithToken);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) meResp.getBody().get("data");
        assertEquals("admin", data.get("role"));
    }

    @Test
    public void testAdminUpdatePermission() {
        String adminToken = login("danny", "danny123");

        // Update smith's permission to view,edit
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("permission", "view,edit");
        ResponseEntity<Map> updateResp = put("/admin/user/smith/permission", adminToken, params);
        assertEquals(200, updateResp.getStatusCodeValue());
        assertEquals("Permission updated", updateResp.getBody().get("msg"));

        // Smith should now be able to access /require_permission
        String smithToken = login("smith", "smith123");
        ResponseEntity<Map> permResp = get("/require_permission", smithToken);
        assertEquals(200, permResp.getStatusCodeValue());

        // /me should show updated permissions
        ResponseEntity<Map> meResp = get("/me", smithToken);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) meResp.getBody().get("data");
        @SuppressWarnings("unchecked")
        java.util.List<String> perms = (java.util.List<String>) data.get("permissions");
        assertTrue(perms.contains("view"));
        assertTrue(perms.contains("edit"));
    }

    @Test
    public void testNonAdminCannotMutate() {
        String smithToken = login("smith", "smith123");

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("role", "user");
        ResponseEntity<Map> resp = put("/admin/user/danny/role", smithToken, params);
        assertEquals(403, resp.getStatusCodeValue());
        assertEquals(403, resp.getBody().get("code"));
    }

    @Test
    public void testAdminUpdateNonExistentUser() {
        String adminToken = login("danny", "danny123");

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("role", "admin");
        ResponseEntity<Map> resp = put("/admin/user/nobody/role", adminToken, params);
        assertEquals(200, resp.getStatusCodeValue());
        assertEquals(404, resp.getBody().get("code"));
        assertEquals("User not found", resp.getBody().get("msg"));
    }

    // ========== Permission Change Reflects Tests ==========

    @Test
    public void testPermissionChangeReflectsInMePermissions() {
        String smithToken = login("smith", "smith123");

        // Before: smith cannot access /require_permission
        ResponseEntity<Map> beforeResp = get("/me/permissions", smithToken);
        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> beforeEndpoints =
                (java.util.List<Map<String, Object>>) beforeResp.getBody().get("data");
        for (Map<String, Object> ep : beforeEndpoints) {
            if ("/require_permission".equals(ep.get("path"))) {
                assertEquals(false, ep.get("accessible"));
            }
        }

        // Admin grants smith view,edit permissions
        String adminToken = login("danny", "danny123");
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("permission", "view,edit");
        put("/admin/user/smith/permission", adminToken, params);

        // After: re-login smith to get fresh token and check /me/permissions
        String newSmithToken = login("smith", "smith123");
        ResponseEntity<Map> afterResp = get("/me/permissions", newSmithToken);
        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> afterEndpoints =
                (java.util.List<Map<String, Object>>) afterResp.getBody().get("data");
        for (Map<String, Object> ep : afterEndpoints) {
            if ("/require_permission".equals(ep.get("path"))) {
                assertEquals(true, ep.get("accessible"));
            }
        }
    }

    // ========== Login Error Tests ==========

    @Test
    public void testLoginWrongPassword() {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("username", "smith");
        params.add("password", "wrong");
        ResponseEntity<Map> resp = restTemplate.postForEntity("/login", params, Map.class);
        assertEquals(401, resp.getStatusCodeValue());
        assertEquals(401, resp.getBody().get("code"));
    }
}
