package com.yujl.component.jwt.enums;

import com.yujl.common.exception.interfaces.ResultInterface;
import lombok.Getter;

/**
 * jwt结果集枚举
 * @author yujl
 * @date 2019/4/13
 */
@Getter
public enum JwtResultEnums implements ResultInterface {

    /**
     * token问题
     */
    TOKEN_ERROR(301, "token无效"),
    TOKEN_EXPIRED(302, "token已过期"),
    NEW_TOKEN(302, "已更新token"),

    /**
     * 账号问题
     */
    AUTH_REQUEST_ERROR(401, "用户名或密码错误"),
    AUTH_REQUEST_LOCKED(402, "该账号已被冻结"),
    AUTH_UNAUTHORIZED(403, "该账号无权限"),
    ;

    private Integer code;

    private String message;

    JwtResultEnums(Integer code, String message) {
        this.code = code;
        this.message = message;
    }
}
