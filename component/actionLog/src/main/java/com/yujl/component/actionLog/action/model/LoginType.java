package com.yujl.component.actionLog.action.model;

import com.yujl.modules.system.enums.ActionLogEnum;
import lombok.Getter;

/**
 * @author yujl
 * @date 2020/10/15
 */
@Getter
public class LoginType extends BusinessType{

    /** 日志类型 */
    protected Byte type = ActionLogEnum.LOGIN.getCode();

    public LoginType(String message) {
        super(message);
    }

    public LoginType(String name, String message) {
        super(name, message);
    }
}
