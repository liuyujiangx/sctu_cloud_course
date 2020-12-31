package com.yujl.devtools.swagger;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @author yujl
 * @date 2020/12/9
 */
@Controller
public class SwaggerController {

    @GetMapping("/dev/swagger")
    public String index(){
        return "redirect:/swagger-ui.html";
    }
}
