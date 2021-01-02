package com.yujl.home.api.controller;

import com.yujl.common.utils.ResultVoUtil;
import com.yujl.common.vo.ResultVo;
import com.yujl.component.jwt.annotation.JwtPermissions;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

/**
 * @author yujl
 * @date 2020/12/14
 */
@Controller
@RequestMapping("/api")
public class TestController {
    /**
     * 设置一条或者多条数据的状态
     */
    @RequestMapping("/test")
    @JwtPermissions("api:test")
    @ResponseBody
    public ResultVo status() {
        // 更新状态
        return ResultVoUtil.success();
    }

    @GetMapping("/err")
    @ResponseBody
    public ResultVo err(String msg){
        if(msg==null){
            msg="未知错误";
        }
        return ResultVoUtil.error(msg);
    }

    /*
    * 获取二维码
    * 二维码的路径
    * 二维码的字符串
    *
    * */
    public ResultVo getLoginQrCode(){
        //1、生成唯一ID
        return ResultVoUtil.success();
    }
}