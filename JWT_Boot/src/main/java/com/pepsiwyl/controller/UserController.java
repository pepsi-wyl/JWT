package com.pepsiwyl.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.pepsiwyl.pojo.User;
import com.pepsiwyl.service.UserService;
import com.pepsiwyl.utils.JWTUtils;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;

/**
 * @author by pepsi-wyl
 * @date 2022-04-17 20:22
 */

@Slf4j

@RestController
@RequestMapping("/user")
public class UserController {

    @Resource(name = "userService")
    private UserService userService;

    @SneakyThrows
    @GetMapping("/login")
    public Map<String, Object> login(@RequestParam("name") String name, @RequestParam("password") String password) {
        log.info("username:" + name + " password:" + password);
        HashMap<String, Object> result = new HashMap<>();

        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("name", name).eq("password", password);
        User user = userService.getOne(wrapper);

        // 登陆成功
        if (user != null) {
            log.info(user.toString());
            // 生成JWTToken
            HashMap<String, String> payload = new HashMap<>();
            payload.put("id", user.getId());
            payload.put("name", user.getName());
            String token = JWTUtils.getToken(payload);
            log.info(token);
            result.put("state", true);
            result.put("msg", "登录成功!!!");
            result.put("token", token);
            return result;
        }

        result.put("state", false);
        result.put("msg", "登录失败!!!");
        return result;
    }
}
