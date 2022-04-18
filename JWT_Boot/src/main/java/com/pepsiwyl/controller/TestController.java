package com.pepsiwyl.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author by pepsi-wyl
 * @date 2022-04-18 19:06
 */

@RestController
@RequestMapping("/test")
public class TestController {
    /**
     * 测试接口
     */
    @GetMapping("/test")
    public Map<String, Object> test(String token) {
        Map<String, Object> map = new HashMap<>();
        map.put("msg", "请求成功~~~");
        map.put("state", true);
        return map;
    }
}
