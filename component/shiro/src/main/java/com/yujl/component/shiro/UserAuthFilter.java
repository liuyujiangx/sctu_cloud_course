package com.yujl.component.shiro;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.http.HttpStatus;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 处理session超时问题拦截器
 *
 * @author yujl
 * @date 2020/8/14
 */
@Slf4j
public class UserAuthFilter extends AccessControlFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        log.info("Admin过滤器");
        if (isLoginRequest(request, response)) {
            return true;
        } else {
            Subject subject = getSubject(request, response);
            return subject.getPrincipal() != null && (subject.isRemembered() || subject.isAuthenticated());
        }
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        if (httpRequest.getHeader("X-Requested-With") != null
                && "XMLHttpRequest".equalsIgnoreCase(httpRequest.getHeader("X-Requested-With"))) {
            System.out.println("if");
            httpResponse.sendError(HttpStatus.UNAUTHORIZED.value());
        } else {
            redirectToLogin(request, response);
        }
        return false;
    }
}
