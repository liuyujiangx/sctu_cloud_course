package com.yujl.component.actionLog.action.model;

import com.yujl.modules.system.enums.ActionLogEnum;
import lombok.Getter;

/**
 * @author yujl
 * @date 2020/10/15
 */
@Getter
public class BusinessMethod extends ActionModel{
    /** 日志名称 */
    protected String name;

    /** 行为方法名 */
    protected String method;

    /** 日志类型 */
    protected Byte type = ActionLogEnum.BUSINESS.getCode();

    /**
     * 只构建行为方法名，日志名称由日志注解name定义
     * @param method 行为方法名
     */
    public BusinessMethod(String method) {
        this.method = method;
    }

    /**
     * 构建日志名称和行为方法名
     * @param name 日志名称
     * @param method 行为方法名
     */
    public BusinessMethod(String name, String method) {
        this.name = name;
        this.method = method;
    }
}
