package com.yujl.admin.api.controller;


import com.yujl.component.jwt.annotation.IgnorePermissions;
import com.yujl.component.jwt.annotation.JwtPermissions;

import com.yujl.modules.api.response.ResponseResult;
import com.yujl.modules.api.service.impl.AuthServiceImpl;
import com.yujl.modules.system.domain.User;
import io.swagger.annotations.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/*
*@Author 19145
*@Date 16:10 2020/12/29
**/
@RestController
@Api(tags = "用户接口")
@Slf4j
@RequestMapping("/api/auth")
public class AuthController {


    @Autowired
    private AuthServiceImpl authService;


    /*
     *@Author 19145
     *@Description 初始化管理员账号
     *@Date 23:36
     *@Param [user]
     *@return com.yujl.blog.response.ResponseResult
     *
     **/
    @PostMapping("/admin_account")
    @JwtPermissions("api:auth:admin_account")
    public ResponseResult initMagegeAccount(@RequestBody User user) {
        log.info("user------>" + user.toString());

        return ResponseResult.SUCCESS().setData(authService.initManagerAccount(user));
    }

    /*
     *@Author 19145
     *@Description 注册
     *@Date 23:50 2020/12/17
     *@Param [user]
     *@return com.yujl.blog.response.ResponseResult
     **/
    @PostMapping("/join_in")
    @IgnorePermissions
    @ApiOperation(value = "jwt注册")
    public ResponseResult regster(@RequestBody User user,
                                  @RequestParam("verfiry_code") String verfiryCode,
                                  @RequestParam("captcha_code") String captchaCode,
                                  @RequestParam("captcha_key") String captchaKey) {
        return authService.register(user, verfiryCode, captchaCode, captchaKey);
    }

    /*
    *@Author 19145
    *@Description 登录
    *@Date 16:00 2020/12/29
    *@Param [username, password, captcha, captchaKey]
    *@return com.yujl.modules.api.response.ResponseResult
    **/
    @IgnorePermissions
    @PostMapping("/login")
    @ApiOperation(value = "jwt登录")
    public ResponseResult auth(
            @ApiParam(value = "用户名", required = true, name = "username") String username,
            @ApiParam(value = "密码", required = true ,name = "password") String password,
            @ApiParam(value = "图灵验证码", required = true ,name = "captcha")String captcha,
            @ApiParam(value = "图灵验证码Key",required = true,name = "captchaKey")String captchaKey) {
        log.info("username---->"+username);
        log.info("password---->"+password);
        log.info("captcha---->"+captcha);
        log.info("captchaKey---->"+captchaKey);
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        return ResponseResult.SUCCESS().setData(authService.doLogin(user,captcha,captchaKey));
    }

    /*
     *@Author 19145
     *@Description 获取图灵验证码
     *@Date 23:40 2020/12/17
     *@Param [发送唯一码，验证时附上]
     *@return com.yujl.blog.response.ResponseResult
     **/
    @IgnorePermissions
    @ApiOperation(value = "获取图灵验证码")
    @GetMapping("/captcha")
    public void getCaptcha(@RequestParam("captcha_key") String captchaKey) {
        try {
            authService.createCaptcha(captchaKey);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
    }

    /*
     *@Author 19145
     *@Description 邮箱获取验证码
     *@Date 23:49 2020/12/17
     *@Param [email]
     *@return com.yujl.blog.response.ResponseResult
     **/
    @IgnorePermissions()
    @ApiOperation(value = "获取邮箱验证码（type=forget或者register）")
    @GetMapping("/verfiry_code")
    public ResponseResult sendVerifyCode(@RequestParam("type") String type,
                                         @RequestParam("email") String email) {
        log.info("email-----》" + email);
        return authService.sendEmail(type, email);
    }

    /*
     *@Author 19145
     *@Description 修改密码
     * 找回密码 通过邮箱验证
     *@Date 23:49 2020/12/17
     *@Param [user]
     *@return com.yujl.blog.response.ResponseResult
     **/
    @PutMapping("/password/{verifyCode}")
    @ApiOperation(value = "修改密码")
    @JwtPermissions("api:auth:password")
    public ResponseResult updatePassword(@PathVariable("verifyCode") String verifyCode,
                                         @RequestBody User user) {
        return authService.updateUserPassword(verifyCode, user);
    }

    /*
     *@Author 19145
     *@Description 修改邮箱
     *@Date 23:04 2020/12/22
     *@Param [verifyCode, email]
     *@return com.yujl.blog.response.ResponseResult
     **/
    @ApiOperation(value = "修改邮箱")
    @PutMapping("/email")
    @JwtPermissions("api:auth:email")
    public ResponseResult updateEmail(@RequestParam("verifyCode") String verifyCode,
                                      @RequestParam("email") String email) {
        return authService.updateUserEmail(verifyCode, email);
    }



    /*
     *@Author 19145
     *@Description 更新用户信息
     *@Date 23:49 2020/12/17
     *
     * 允许用户更改的内容
     * 头像
     * 用户名
     * 密码   单独 修改
     * 前面
     * email  单独修改
     *@Param [user]
     *@return com.yujl.blog.response.ResponseResult
     **/
    @PutMapping("/user_info/{userId}")
    @ApiOperation(value = "更新用户信息")
    @JwtPermissions("api:auth:edit_user_info")
    public ResponseResult updateUserInfo(@PathVariable("userId") Long userId,
                                         @RequestBody User user) {
        return authService.updateUserInfo(userId, user);
    }

    /*
     *@Author 19145
     *@Description 检查该email是否被注册
     *@Date 16:34 2020/12/22
     *@Param [email]
     *@return com.yujl.blog.response.ResponseResult
     **/
    @ApiResponses({
            @ApiResponse(code = 20000, message = "表示当前邮箱已经被注册"),
            @ApiResponse(code = 40000, message = "表示当前邮箱未被注册")
    })
    @ApiOperation(value = "检查email是否被注册")
    @GetMapping("email")
    @IgnorePermissions
    public ResponseResult checkEmail(@RequestParam("email") String email) {
        return authService.checkEmail(email);
    }

    /*
     *@Author 19145
     *@Description 检查该userName是否被注册
     *@Date 16:44 2020/12/22
     *@Param [userName]
     *@return com.yujl.blog.response.ResponseResult
     **/
    @IgnorePermissions
    @ApiResponses({
            @ApiResponse(code = 20000, message = "表示当前用户名已经被注册"),
            @ApiResponse(code = 40000, message = "表示当前用户名未被注册")
    })
    @GetMapping("user_mame")
    @ApiOperation(value = "检查用户名是否被注册")
    public ResponseResult checkUserName(@RequestParam("userName") String userName) {
        return authService.checkUserName(userName);
    }

    @IgnorePermissions
    @GetMapping("/logout")
    public ResponseResult logout() {
        return authService.doLogout();
    }
}
