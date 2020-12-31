package com.yujl.component.jwt.utlis;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.yujl.common.exception.ResultException;
import com.yujl.common.utils.Constans;
import com.yujl.common.utils.HttpServletUtil;
import com.yujl.common.utils.RedisUtil;
import com.yujl.common.utils.ToolUtil;
import com.yujl.component.jwt.config.properties.JwtProjectProperties;
import com.yujl.component.jwt.enums.JwtResultEnums;
import com.yujl.modules.system.domain.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Calendar;
import java.util.Date;

/**
 * @author 小懒虫
 * @date 2019/4/9
 */
@Component
@Slf4j
public class JwtUtil {

    @Autowired
    private JwtProjectProperties jwtProjectProperties;

    @Autowired
    private  RedisUtil redisUtil;

    private static JwtUtil jwtUtil;

    @PostConstruct
    public void init() {
        jwtUtil = this;
        jwtUtil.jwtProjectProperties = jwtProjectProperties;
        jwtUtil.redisUtil = redisUtil;
    }

    /**
     * 生成JwtToken
     *
     * @param username 用户名
     * @param secret   秘钥
     * @param amount   过期天数
     */
    public static String getToken(String username, String secret, int amount) {
        User user = new User();
        user.setUsername(username);
        return getToken(user, secret, amount);
    }

    /**
     * 生成JwtToken
     *
     * @param user   用户对象
     * @param secret 秘钥
     * @param amount 过期天数
     */
    public static String getToken(User user, String secret, int amount) {
        // 过期时间
        Calendar ca = Calendar.getInstance();
        ca.add(Calendar.DATE, amount);

        // 随机Claim
        String random = ToolUtil.getRandomString(6);

        // 创建JwtToken对象
        String token = "";
        token = JWT.create()
                // 用户名
                .withSubject(user.getUsername())
                // 发布时间
                .withIssuedAt(new Date())
                // 过期时间
                .withExpiresAt(ca.getTime())
                // 自定义随机Claim
                .withClaim("ran", random)
                .sign(getSecret(secret, random));

        return token;
    }

    /**
     * 获取请求对象中的token数据
     */
    public static String getRequestToken(HttpServletRequest request) {
        // 获取JwtTokens失败
        String authorization = request.getHeader("Authorization");
        log.info("tokenKey(authorization)------>" + authorization);
        if (authorization == null) {
            throw new ResultException(JwtResultEnums.TOKEN_ERROR);
        }
        String token = (String) jwtUtil.redisUtil.get(Constans.User.KEY_TOKEN + authorization);
        if (token == null) {
            throw new ResultException(JwtResultEnums.TOKEN_EXPIRED);
        }
        log.info("token------>" + token);
        return token;
    }

    /**
     * 获取当前token中的用户名
     */
    public static String getSubject() {
        HttpServletRequest request = HttpServletUtil.getRequest();
        String token = getRequestToken(request);
        return JWT.decode(token).getSubject();
    }

    /**
     * 验证JwtToken
     *
     * @param token JwtToken数据
     * @return true 验证通过
     * @throws TokenExpiredException    Token过期
     * @throws JWTVerificationException 令牌无效（验证不通过）
     */
    public static void verifyToken(String token) throws JWTVerificationException {
        String ran = JWT.decode(token).getClaim("ran").asString();
        String secret = jwtUtil.jwtProjectProperties.getSecret();
        JWTVerifier jwtVerifier = JWT.require(getSecret(secret, ran)).build();
        jwtVerifier.verify(token);
    }

    /**
     * 生成Secret混淆数据
     */
    private static Algorithm getSecret(String secret, String random) {
        String salt = "君不见黄河之水天上来，奔流到海不复回。君不见高堂明镜悲白发，朝如青丝暮成雪。";
        //String salt = "元嘉草草，封狼居胥，赢得仓皇北顾。四十三年，望中犹记，烽火扬州路。可堪回首，佛狸祠下，一片神鸦社鼓。凭谁问、廉颇老矣，尚能饭否？";
        //String salt = "安能摧眉折腰事权贵，使我不得开心颜。";
        //String salt = "大江东去，浪淘尽，千古风流人物。故垒西边，人道是，三国周郎赤壁。乱石穿空，惊涛拍岸，卷起千堆雪。江山如画，一时多少豪杰。";
        return Algorithm.HMAC256(secret + salt + "(ノ￣▽￣)ノ 皮一下" + random);
    }
}
