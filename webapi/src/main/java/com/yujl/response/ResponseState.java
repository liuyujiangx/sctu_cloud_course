package com.yujl.response;

public enum  ResponseState {
    SUCCESS(20000,"操作成功",true),
    GET_RESOURCE_FAILED(40001, "获取资源失败", false),
    AUCCOUNT_NOT_LOGIN(40002, "账号未登录", false),
    AUCCOUNT_UNAUTHORIZED(40003, "账号没有权限", false),
    AUCCOUNT_DENIED(40003, "账号已被冻结", false),
    ERROR_403(40003, "权限不足", false),
    ERROR_404(40003, "页面丢失", false),
    ERROR_504(40003, "系统繁忙，请稍后重试", false),
    ERROR_505(40003, "请求错误，请检查参数", false),
    LOGIN_FAILED(49999, "登录失败", false),
    LOGIN_SUCCESS(20001, "登录成功", true),
    RGESGIR_SUCCESS(20002, "注册成功", true),
    FAILED(40000,"操作失败",false);
    ResponseState(int code, String message, boolean success) {
        this.code = code;
        this.message = message;
        this.success = success;
    }
    private int code;

    private String message;

    private boolean success;



    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }
}
