package org.inlighting.shiro;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * Registers the {@link FallbackAuthInterceptor} so that it runs
 * <b>after</b> the Shiro/JWT filter but <b>before</b> the controller
 * method is invoked.
 */
@Configuration
public class WebMvcConfig extends WebMvcConfigurerAdapter {

    private final FallbackAuthInterceptor fallbackAuthInterceptor;

    @Autowired
    public WebMvcConfig(FallbackAuthInterceptor fallbackAuthInterceptor) {
        this.fallbackAuthInterceptor = fallbackAuthInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(fallbackAuthInterceptor);
    }
}
