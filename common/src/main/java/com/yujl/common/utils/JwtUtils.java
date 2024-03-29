package com.yujl.common.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
@Component
public class JwtUtils {

    //盐值
    private static String key = "a020e1e34e671e63c7bd6bd951769c5a";

    private static long ttl = 3*60*60*1000;//2个小时

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        JwtUtils.key = key;
    }

    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        JwtUtils.ttl = ttl;
    }

    /**
     * @param claims 载荷内容
     * @param ttl    有效时长
     * @return
     */


    public static String createToken(Map<String ,Object> claims,long ttl) {
        JwtUtils.ttl = ttl;
        return createToken(claims);
    }


    public static String createRefreshToken(String userId, long ttl) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        JwtBuilder builder = Jwts.builder().setId(userId)
                .setIssuedAt(now)
                .signWith(SignatureAlgorithm.HS256, JwtUtils.key);
        if (ttl > 0) {
            builder.setExpiration(new Date(nowMillis + ttl));
        }
        return builder.compact();
    }

    /**
     * @param claims 载荷
     * @return token
     */
    public static String createToken(Map<String, Object> claims) {

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        JwtBuilder builder = Jwts.builder()
                .setIssuedAt(now)
                .signWith(SignatureAlgorithm.HS256, key);

        if (claims != null) {
            builder.setClaims(claims);
        }

        if (ttl > 0) {
            builder.setExpiration(new Date(nowMillis + ttl));
        }
        return builder.compact();
    }


    public static Claims parseJWT(String jwtStr) {
        return Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(jwtStr)
                .getBody();
    }



}
