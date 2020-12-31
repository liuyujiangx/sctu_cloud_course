package com.yujl.service;

import com.yujl.response.ResponseResult;
import com.yujl.modules.system.domain.User;

import java.awt.*;
import java.io.IOException;

public interface AuthService {
    ResponseResult initManagerAccount(User user);

    void createCaptcha( String captchaKey) throws IOException, FontFormatException;

    ResponseResult sendEmail(String type,String email);

    ResponseResult register(User user, String verfiryCode,
                            String captchaCode, String captchaKey);

    ResponseResult doLogin(User user, String captcha,
                           String captchaKey);

    User checkUser();

    ResponseResult checkEmail(String email);

    ResponseResult checkUserName(String userName);

    ResponseResult updateUserInfo(Long userId, User user);

    ResponseResult updateUserPassword(String verifyCode,String email,String password );

    ResponseResult updateUserEmail(String verifyCode, String email);

    ResponseResult doLogout();
}
