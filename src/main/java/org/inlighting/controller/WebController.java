package org.inlighting.controller;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.*;
import org.apache.shiro.subject.Subject;
import org.inlighting.bean.ResponseBean;
import org.inlighting.database.UserService;
import org.inlighting.database.UserBean;
import org.inlighting.exception.UnauthorizedException;
import org.inlighting.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
public class WebController {

    private static final Logger LOGGER = LogManager.getLogger(WebController.class);

    private UserService userService;

    @Autowired
    public void setService(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/login")
    public ResponseBean login(@RequestParam("username") String username,
                              @RequestParam("password") String password) {
        UserBean userBean = userService.getUser(username);
        if (userBean.getPassword().equals(password)) {
            return new ResponseBean(200, "Login success", JWTUtil.sign(username, password));
        } else {
            throw new UnauthorizedException();
        }
    }

    @GetMapping("/article")
    public ResponseBean article() {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            return new ResponseBean(200, "You are already logged in", null);
        } else {
            return new ResponseBean(200, "You are guest", null);
        }
    }

    @GetMapping("/require_auth")
    @RequiresAuthentication
    public ResponseBean requireAuth() {
        return new ResponseBean(200, "You are authenticated", null);
    }

    @GetMapping("/require_role")
    @RequiresRoles("admin")
    public ResponseBean requireRole() {
        return new ResponseBean(200, "You are visiting require_role", null);
    }

    @GetMapping("/require_permission")
    @RequiresPermissions(logical = Logical.AND, value = {"view", "edit"})
    public ResponseBean requirePermission() {
        return new ResponseBean(200, "You are visiting permission require edit,view", null);
    }

    @GetMapping("/me")
    @RequiresAuthentication
    public ResponseBean me() {
        String token = (String) SecurityUtils.getSubject().getPrincipal();
        String username = JWTUtil.getUsername(token);
        UserBean user = userService.getUser(username);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("username", user.getUsername());
        data.put("role", user.getRole());
        data.put("permissions", Arrays.asList(user.getPermission().split(",")));
        data.put("tokenExpiresAt", JWTUtil.getExpiresAt(token));
        return new ResponseBean(200, "ok", data);
    }

    @GetMapping("/me/permissions")
    @RequiresAuthentication
    public ResponseBean mePermissions() {
        String token = (String) SecurityUtils.getSubject().getPrincipal();
        String username = JWTUtil.getUsername(token);
        UserBean user = userService.getUser(username);

        String role = user.getRole();
        Set<String> perms = new HashSet<>(Arrays.asList(user.getPermission().split(",")));

        List<Map<String, Object>> endpoints = new ArrayList<>();

        // Public endpoints
        endpoints.add(buildEndpoint("POST", "/login", false, true));
        endpoints.add(buildEndpoint("GET", "/article", false, true));

        // Auth-only
        endpoints.add(buildEndpoint("GET", "/require_auth", true, true));
        endpoints.add(buildEndpoint("GET", "/me", true, true));
        endpoints.add(buildEndpoint("GET", "/me/permissions", true, true));

        // Role-based
        boolean isAdmin = "admin".equals(role);
        endpoints.add(buildEndpoint("GET", "/require_role", true, isAdmin));
        endpoints.add(buildEndpoint("PUT", "/admin/user/{username}/role", true, isAdmin));
        endpoints.add(buildEndpoint("PUT", "/admin/user/{username}/permission", true, isAdmin));

        // Permission-based
        boolean hasViewEdit = perms.contains("view") && perms.contains("edit");
        endpoints.add(buildEndpoint("GET", "/require_permission", true, hasViewEdit));

        return new ResponseBean(200, "ok", endpoints);
    }

    private Map<String, Object> buildEndpoint(String method, String path, boolean requireAuth, boolean accessible) {
        Map<String, Object> ep = new LinkedHashMap<>();
        ep.put("method", method);
        ep.put("path", path);
        ep.put("requireAuth", requireAuth);
        ep.put("accessible", accessible);
        return ep;
    }

    @PutMapping("/admin/user/{username}/role")
    @RequiresRoles("admin")
    public ResponseBean updateUserRole(@PathVariable("username") String username,
                                       @RequestParam("role") String role) {
        UserBean user = userService.getUser(username);
        if (user == null) {
            return new ResponseBean(404, "User not found", null);
        }
        userService.updateRole(username, role);
        return new ResponseBean(200, "Role updated", null);
    }

    @PutMapping("/admin/user/{username}/permission")
    @RequiresRoles("admin")
    public ResponseBean updateUserPermission(@PathVariable("username") String username,
                                             @RequestParam("permission") String permission) {
        UserBean user = userService.getUser(username);
        if (user == null) {
            return new ResponseBean(404, "User not found", null);
        }
        userService.updatePermission(username, permission);
        return new ResponseBean(200, "Permission updated", null);
    }

    @RequestMapping(path = "/401")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseBean unauthorized() {
        return new ResponseBean(401, "Unauthorized", null);
    }
}
