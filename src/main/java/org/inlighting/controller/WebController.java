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
        if (userBean != null && userBean.getPassword().equals(password)) {
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

    // ========== 新增 API：个人资料与权限自助查询 ==========

    /**
     * 查看当前登录用户的用户名、角色、权限和 token 过期时间
     */
    @GetMapping("/me")
    @RequiresAuthentication
    public ResponseBean me() {
        Subject subject = SecurityUtils.getSubject();
        String token = subject.getPrincipal().toString();
        String username = JWTUtil.getUsername(token);
        UserBean user = userService.getUser(username);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("username", user.getUsername());
        data.put("role", user.getRole());
        data.put("permissions", Arrays.asList(user.getPermission().split(",")));

        Date expireTime = JWTUtil.getExpireTime(token);
        data.put("tokenExpireTime", expireTime != null ? expireTime.getTime() : null);

        return new ResponseBean(200, "OK", data);
    }

    /**
     * 查看当前 token 可访问的受保护接口清单
     */
    @GetMapping("/me/permissions")
    @RequiresAuthentication
    public ResponseBean myPermissions() {
        Subject subject = SecurityUtils.getSubject();

        // 定义受保护的接口清单及其所需权限/角色
        List<Map<String, Object>> endpoints = new ArrayList<>();

        // /require_auth — 只需要认证
        Map<String, Object> authEndpoint = new LinkedHashMap<>();
        authEndpoint.put("path", "/require_auth");
        authEndpoint.put("requiredAuth", "authenticated");
        authEndpoint.put("accessible", subject.isAuthenticated());
        endpoints.add(authEndpoint);

        // /require_role — 需要 admin 角色
        Map<String, Object> roleEndpoint = new LinkedHashMap<>();
        roleEndpoint.put("path", "/require_role");
        roleEndpoint.put("requiredRole", "admin");
        roleEndpoint.put("accessible", subject.hasRole("admin"));
        endpoints.add(roleEndpoint);

        // /require_permission — 需要 view 和 edit 权限
        Map<String, Object> permEndpoint = new LinkedHashMap<>();
        permEndpoint.put("path", "/require_permission");
        permEndpoint.put("requiredPermissions", Arrays.asList("view", "edit"));
        permEndpoint.put("accessible",
                subject.isPermitted("view") && subject.isPermitted("edit"));
        endpoints.add(permEndpoint);

        return new ResponseBean(200, "OK", endpoints);
    }

    // ========== 新增 API：管理员调整用户角色和权限 ==========

    /**
     * 管理员更新用户角色
     */
    @PutMapping("/admin/user/{username}/role")
    @RequiresRoles("admin")
    public ResponseBean updateUserRole(@PathVariable("username") String username,
                                       @RequestParam("role") String role) {
        boolean success = userService.updateRole(username, role);
        if (success) {
            return new ResponseBean(200, "Role updated", null);
        } else {
            return new ResponseBean(404, "User not found", null);
        }
    }

    /**
     * 管理员更新用户权限
     */
    @PutMapping("/admin/user/{username}/permission")
    @RequiresRoles("admin")
    public ResponseBean updateUserPermission(@PathVariable("username") String username,
                                             @RequestParam("permission") String permission) {
        boolean success = userService.updatePermission(username, permission);
        if (success) {
            return new ResponseBean(200, "Permission updated", null);
        } else {
            return new ResponseBean(404, "User not found", null);
        }
    }

    @RequestMapping(path = "/401")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseBean unauthorized() {
        return new ResponseBean(401, "Unauthorized", null);
    }
}
