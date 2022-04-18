package com.pepsiwyl.config;

import com.pepsiwyl.Interceptor.JwtTokenInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.Resource;

/**
 * @author by pepsi-wyl
 * @date 2022-04-17 21:03
 */

@Configuration
public class WebMVCConfig implements WebMvcConfigurer {

    // 注入拦截器
    @Resource(name = "jwtTokenInterceptor")
    JwtTokenInterceptor jwtTokenInterceptor;

    // 配置拦截器
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(jwtTokenInterceptor).
                excludePathPatterns("/user/login") // 放行路径
                .addPathPatterns("/**");      // 拦截路径
    }

}
