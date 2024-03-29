package com.yujl.component.actionLog.action.model;

import com.yujl.modules.system.enums.ActionLogEnum;
import lombok.Getter;

/**
 * @author yujl
 * @date 2020/10/15
 */
@Getter
public class LoginMethod extends BusinessMethod{

    /** 日志类型 */
    protected Byte type = ActionLogEnum.LOGIN.getCode();

    public LoginMethod(String method) {
        super(method);
    }

    public LoginMethod(String name, String method) {
        super(name, method);
    }
}
