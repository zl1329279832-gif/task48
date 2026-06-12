package org.inlighting.database;

import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class UserService {

    public UserBean getUser(String username) {
        // 没有此用户直接返回null
        if (! DataSource.getData().containsKey(username))
            return null;

        UserBean user = new UserBean();
        Map<String, String> detail = DataSource.getData().get(username);

        user.setUsername(username);
        user.setPassword(detail.get("password"));
        user.setRole(detail.get("role"));
        user.setPermission(detail.get("permission"));
        return user;
    }

    /**
     * 更新用户角色
     */
    public boolean updateRole(String username, String role) {
        if (!DataSource.getData().containsKey(username)) {
            return false;
        }
        DataSource.getData().get(username).put("role", role);
        return true;
    }

    /**
     * 更新用户权限
     */
    public boolean updatePermission(String username, String permission) {
        if (!DataSource.getData().containsKey(username)) {
            return false;
        }
        DataSource.getData().get(username).put("permission", permission);
        return true;
    }
}
