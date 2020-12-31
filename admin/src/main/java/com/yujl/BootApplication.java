package com.yujl;

import com.google.gson.Gson;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * @author yujl
 * @date 2020/8/14
 */
@SpringBootApplication
@EnableJpaAuditing // 使用jpa自动赋值
@EnableCaching // 开启缓存
public class BootApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplication.run(BootApplication.class, args);
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(BootApplication.class);
    }

    @Bean
    public Gson createGson(){
        return new Gson();
    }
}
