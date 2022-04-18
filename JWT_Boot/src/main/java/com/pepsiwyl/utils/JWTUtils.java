package com.pepsiwyl.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Map;

/**
 * @author by pepsi-wyl
 * @date 2022-04-17 19:42
 */

public class JWTUtils {

    // 密钥
    private static final String SING = "f4e2e52034348f86b67cde581c0f9eb5";
    // 过期天数
    private static final Integer DAYS = 7;

    /**
     * 创建Token
     *
     * @param map 参数列表
     * @return
     */
    public static String getToken(Map<String, String> map) {
        // 创建 jwtBuilder
        JWTCreator.Builder builder = JWT.create();
        // payload
        map.forEach((k, v) -> {
            builder.withClaim(k, v);
        });
        // 过期时间
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, DAYS);
        builder.withExpiresAt(calendar.getTime());
        // 签名
        return builder.sign(Algorithm.HMAC256(SING));
    }

    /**
     * 获取Token 中 payload
     *
     * @param token
     * @return
     */
    public static DecodedJWT verifyToken(String token) {
        return JWT.require(Algorithm.HMAC256(SING)).build().verify(token);
    }

}
