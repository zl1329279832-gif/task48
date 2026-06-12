package org.inlighting.shiro;

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Safety-net interceptor that runs AFTER JWTFilter but BEFORE the
 * controller method.  When the filter marked the request as
 * "authentication attempted but failed" (AUTH_FAILED_ATTR) and the
 * target handler carries a Shiro authorization annotation, we throw
 * UnauthenticatedException immediately instead of letting the request
 * silently degrade to guest logic.
 *
 * Endpoints without Shiro annotations (e.g. /article) are not affected,
 * so legitimate guest access still works.
 */
@Component
public class FallbackAuthInterceptor extends HandlerInterceptorAdapter {

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        Boolean authFailed = (Boolean) request.getAttribute(JWTFilter.AUTH_FAILED_ATTR);
        if (authFailed != null && authFailed && requiresShiroAuth((HandlerMethod) handler)) {
            throw new UnauthenticatedException();
        }
        return true;
    }

    private boolean requiresShiroAuth(HandlerMethod method) {
        return method.hasMethodAnnotation(RequiresAuthentication.class)
                || method.hasMethodAnnotation(RequiresRoles.class)
                || method.hasMethodAnnotation(RequiresPermissions.class)
                || method.hasMethodAnnotation(RequiresUser.class);
    }
}
