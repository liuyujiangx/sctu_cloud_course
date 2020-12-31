package com.yujl.common.utils;

import com.yujl.modules.system.service.impl.UserServiceImpl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * 密码加密测试类，可用于重置密码
 * @author 小懒虫
 * @date 2019/4/27
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class EncryptUtilTest {
    @Autowired
    private UserServiceImpl userService;

    @Test
    public void encrypt() {
//        String password = "123456";
//        String salt = "abcdef";
//
//        String encrypt = EncryptUtil.encrypt(password, salt);
//        System.out.println("明文密码：" + password);
//        System.out.println("密码盐：" + salt);
//        System.out.println("混淆密码：" + encrypt);
        //redisUtil.set("123",123);
//        User admin = userService.getByName("admin");
//        System.out.println(admin.getStatus().intValue());
//        System.out.println(admin.getStatus());

    }
}