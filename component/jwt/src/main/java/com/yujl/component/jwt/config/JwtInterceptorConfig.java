package com.yujl.component.jwt.config;

import com.yujl.component.jwt.interceptor.AuthenticationInterceptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * jwt权限配置拦截器
 * @author yujl
 * @date 2019/4/12
 */
@SpringBootConfiguration
@Slf4j
@ConditionalOnProperty(name = "project.jwt.pattern-path", havingValue = "true")
public class JwtInterceptorConfig implements WebMvcConfigurer {
    @Autowired
    private AuthenticationInterceptor authenticationInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        log.info("JwtInterceptorConfig.addInterceptors");
        registry.addInterceptor(authenticationInterceptor).addPathPatterns("/api/**");
    }
}
