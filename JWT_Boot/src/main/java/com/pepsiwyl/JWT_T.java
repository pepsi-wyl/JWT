package com.pepsiwyl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;

import java.util.Calendar;
import java.util.HashMap;

/**
 * @author by pepsi-wyl
 * @date 2022-04-17 19:04
 */

@Slf4j

public class JWT_T {
    public static void main(String[] args) {

        HashMap<String, Object> map = new HashMap<>(); // header
        Calendar calendar = Calendar.getInstance();    // 过期时间
        calendar.add(Calendar.MINUTE, 10);     // 10分钟过期

        /**
         * 令牌的获取
         */
        String token = JWT.create()
                // 设置过期时间
                .withExpiresAt(calendar.getTime())
                // 设置头信息
                .withHeader(map)
                // 设置负载信息
                .withClaim("userId", 1001)
                .withClaim("userName", "pepsi-wyl")
                // 设置签名 密钥
                .sign(Algorithm.HMAC256("@#$%{^&*-&*)]k[{8{}"));
        log.info(token);

        /**
         * 令牌的验证
         */
//        String tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NTAxOTYwNTYsInVzZXJOYW1lIjoicGVwc2ktd3lsIiwidXNlcklkIjoxMDAxfQ.9XkItANWDSmT0A_DE_KqcDJNgHw-JytcndVJeE3WqAg";
//        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("@#$%{^&*-&*)]k[{8{}")).build();
//        DecodedJWT verify = jwtVerifier.verify(tokenStr);
//        log.info("userId", verify.getClaim("userId").asInt().toString());
//        log.info("userName", verify.getClaim("userName").asString());
//        log.info("过期时间", verify.getExpiresAt().toString());

    }


}
