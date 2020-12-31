package com.yujl.component.jwt.annotation;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.yujl.common.constant.AdminConst;
import com.yujl.common.enums.StatusEnum;
import com.yujl.common.exception.ResultException;
import com.yujl.common.utils.JwtUtils;
import com.yujl.common.utils.RedisUtil;
import com.yujl.component.jwt.config.properties.JwtProjectProperties;
import com.yujl.component.jwt.enums.JwtResultEnums;
import com.yujl.component.jwt.utlis.JwtUtil;
import com.yujl.modules.system.domain.Menu;
import com.yujl.modules.system.domain.Role;
import com.yujl.modules.system.domain.User;
import com.yujl.modules.system.service.impl.UserServiceImpl;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Set;

/**
 * Jwt权限注解AOP
 * @author 小懒虫
 * @date 2019/4/13
 */
@Slf4j
@Aspect
@Component
@ConditionalOnProperty(name = "project.jwt.pattern-anno", havingValue = "true", matchIfMissing = true)
public class JwtPermissionsAop {

    @Autowired
    private JwtProjectProperties jwtProperties;

    @Autowired
    private HttpServletRequest request;

    @Autowired
    private UserServiceImpl userService;

    @Resource
    private RedisUtil redisUtil;

    @Pointcut("@annotation(com.yujl.component.jwt.annotation.JwtPermissions)")
    public void jwtPermissions() {};

    @Around("@annotation(jwtPermissions)")
    public Object doPermission(ProceedingJoinPoint point,JwtPermissions jwtPermissions) throws Throwable {

        // 获取请求对象头部token数据
        String token = JwtUtil.getRequestToken(request);
        boolean isAllowd = true;
        try {
            Claims claims = JwtUtils.parseJWT(token);
            User user = userService.getByName((String) claims.get("userName"));
            Set<Role> roles;
            try {
                roles = (Set<Role>) redisUtil.get("user-role-perms"+user.getId());
                if (user.getId().equals(AdminConst.ADMIN_ID)){
                    return point.proceed();
                }
                for (Role role:roles) {
                    for (Menu menu:role.getMenus()) {
                        String perms = menu.getPerms();
                        if (menu.getStatus().equals(StatusEnum.OK.getCode())
                                && !StringUtils.isEmpty(perms) && !perms.contains("*")) {
                            if (perms.equals(jwtPermissions.value())){
                                isAllowd = false;
                            }
                        }
                    }
                }
            }catch (Exception e){
                if (user.getId().equals(AdminConst.ADMIN_ID)){
                    return point.proceed();
                }
                roles = user.getRoles();
                for (Role role:roles) {
                    for (Menu menu:role.getMenus()) {
                        String perms = menu.getPerms();
                        if (menu.getStatus().equals(StatusEnum.OK.getCode())
                                && !StringUtils.isEmpty(perms) && !perms.contains("*")) {
                            if (perms.equals(jwtPermissions.value())){
                                isAllowd = false;
                            }
                        }
                    }
                }
                log.info("roles---------->"+roles.size());
                redisUtil.set("user-role-perms"+user.getId(),roles,60*60*24*30);
            }

            if (isAllowd){
                throw new ResultException(JwtResultEnums.AUTH_UNAUTHORIZED);
            }
        } catch (TokenExpiredException e) {
            log.info("token过期------>"+e.getMessage());
            throw new ResultException(JwtResultEnums.TOKEN_EXPIRED);
        } catch (JWTVerificationException e) {
            log.info("token错误------>"+e.getMessage());
            throw new ResultException(JwtResultEnums.TOKEN_ERROR);
        }

        return point.proceed();
    }

}
