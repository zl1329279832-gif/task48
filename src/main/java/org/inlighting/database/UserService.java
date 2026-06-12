package org.inlighting.database;

import org.inlighting.shiro.MyRealm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class UserService {

    private MyRealm myRealm;

    /**
     * 使用 setter + @Lazy 注入，避免与 MyRealm 之间的循环依赖。
     * MyRealm 也依赖 UserService，@Lazy 延迟到首次使用时才解析。
     */
    @Autowired
    @Lazy
    public void setMyRealm(MyRealm myRealm) {
        this.myRealm = myRealm;
    }

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
        // 角色变更后清除该用户的授权缓存，确保旧 token 立即失效旧权限
        if (myRealm != null) {
            myRealm.clearAuthorizationCache();
        }
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
        // 权限变更后清除该用户的授权缓存
        if (myRealm != null) {
            myRealm.clearAuthorizationCache();
        }
        return true;
    }
}
