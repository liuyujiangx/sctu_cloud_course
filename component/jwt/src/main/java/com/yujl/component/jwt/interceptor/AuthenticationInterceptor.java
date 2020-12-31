package com.yujl.component.jwt.interceptor;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.yujl.common.enums.StatusEnum;
import com.yujl.common.exception.ResultException;
import com.yujl.component.jwt.annotation.IgnorePermissions;
import com.yujl.component.jwt.annotation.JwtPermissions;
import com.yujl.component.jwt.config.properties.JwtProjectProperties;
import com.yujl.component.jwt.enums.JwtResultEnums;
import com.yujl.component.jwt.utlis.JwtUtil;
import com.yujl.component.shiro.ShiroUtil;
import com.yujl.modules.system.domain.Menu;
import com.yujl.modules.system.domain.Role;
import com.yujl.modules.system.service.impl.UserServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.util.Set;

/**
 * jwt权限拦截器
 * @author yujl
 * @date 2019/4/12
 */
@Slf4j
@Component
public class AuthenticationInterceptor implements HandlerInterceptor {

    @Autowired
    private JwtProjectProperties jwtProperties;

    @Autowired
    private UserServiceImpl userService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 如果不是映射到方法直接通过
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        // 判断请求映射的方式是否忽略权限验证
        HandlerMethod handlerMethod=(HandlerMethod) handler;
        Method method=handlerMethod.getMethod();
        if (method.isAnnotationPresent(IgnorePermissions.class)) {
            return true;
        }

        // 获取请求对象头部token数据
        String token = JwtUtil.getRequestToken(request);
        log.info("token------>"+token);

        JwtPermissions jwtPermissions = handlerMethod.getMethodAnnotation(JwtPermissions.class);
        log.info("jwtPermissions------->"+ jwtPermissions.value());

//        roles.forEach(role -> {
//            log.info("role-------->"+role.getName());
//            role.getMenus().forEach(menu -> {
//                String perms = menu.getPerms();
//                if (menu.getStatus().equals(StatusEnum.OK.getCode())
//                        && !StringUtils.isEmpty(perms) && !perms.contains("*")) {
//                    log.info("perms------->"+perms);
//                    boolean xx = isAllowd;
//                    if (perms.equals(jwtPermissions)){
//                        xx = true;
//                    }
//                }
//            });
//        });
        // 验证token数据是否正确
        try {
            JwtUtil.verifyToken(token);
//            Set<Role> roles = userService.getByName(JwtUtil.getSubject()).getRoles();
//            for (Role role:roles) {
//                for (Menu menu:role.getMenus()) {
//                    String perms = menu.getPerms();
//                    if (menu.getStatus().equals(StatusEnum.OK.getCode())
//                            && !StringUtils.isEmpty(perms) && !perms.contains("*")) {
//                        log.info("perms------->"+perms);
//                        if (perms.equals(jwtPermissions.value())){
//                            return true;
//                        }
//                    }
//                }
//            }
        } catch (TokenExpiredException e) {
            log.info("token过期------>"+e.getMessage());
            throw new ResultException(JwtResultEnums.TOKEN_EXPIRED);
        } catch (JWTVerificationException e) {
            log.info("token错误------>"+e.getMessage());
            throw new ResultException(JwtResultEnums.TOKEN_ERROR);
        }

        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {

    }
}
