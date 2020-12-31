package com.yujl.service.impl;

import com.google.gson.Gson;
import com.wf.captcha.SpecCaptcha;
import com.wf.captcha.base.Captcha;
import com.yujl.common.utils.*;
import com.yujl.component.jwt.utlis.JwtUtil;
import com.yujl.component.shiro.ShiroUtil;
import com.yujl.domain.TbRefreshToken;
import com.yujl.domain.TbSettings;
import com.yujl.modules.system.utils.ClaimsUtil;
import com.yujl.repository.RefreshTokenDao;
import com.yujl.repository.SettingsDao;
import com.yujl.response.ResponseResult;
import com.yujl.service.AuthService;
import com.yujl.modules.system.domain.User;
import com.yujl.modules.system.repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import java.awt.*;
import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.Random;

@Service
@Transactional
@Slf4j
public class AuthServiceImpl implements AuthService {


    private final SnowflakeIdWorker idWorker = new SnowflakeIdWorker(0, 0);

    @Autowired
    private UserRepository userDao;

    @Autowired
    private SettingsDao settingsDao;

    @Autowired
    private RedisUtils redisUtils;

    @Autowired
    private RefreshTokenDao refreshTokenDao;

    @Autowired
    private Gson gson;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private JwtUtils jwtUtils;

    @Override
    public ResponseResult initManagerAccount(User user) {
        //检查数据是否有初始化

        TbSettings managerAccountState = settingsDao.findOneByKey(Constans.Setting.MANAGER_ACCOUNT_INIT_STATE);

        if (managerAccountState != null) {
            return ResponseResult.FAILED("已经初始化过了");
        }
        //TODO
        //检查数据
        if (TextUtils.isEmpty(user.getUsername())) {
            return ResponseResult.FAILED("用户名不能为空");
        }
        if (TextUtils.isEmpty(user.getPassword())) {
            return ResponseResult.FAILED("密码不能为空");
        }

        if (TextUtils.isEmpty(user.getEmail())) {
            return ResponseResult.FAILED("邮箱不能为空");
        }
        //补充数据

        //user.setRoles(Constans.User.ROLE_ADMIN);
        user.setPicture(Constans.User.DEFAULT_AVATAR);
        //user.setStatus(Constans.User.DEFAULT_STATE);
        //user.setCreateTime(new Date());
        //user.setUpdateTime(new Date());
        //对密码进行加密
        String salt = ShiroUtil.getRandomSalt();
        String encrypt = ShiroUtil.encrypt(user.getPassword(), salt);
        user.setPassword(encrypt);
        //保存到数据库中
        userDao.save(user);
        //更新已添加的标记

        TbSettings settings = new TbSettings();
        settings.setId(idWorker.nextId() + "");
        settings.setKey(Constans.Setting.MANAGER_ACCOUNT_INIT_STATE);
        settings.setCreateTime(new Date());
        settings.setUpdateTime(new Date());
        settings.setValue("1");
        settingsDao.save(settings);


        return ResponseResult.SUCCESS("初始化成功");
    }

    @Override
    public void createCaptcha(String captchaKey) throws IOException, FontFormatException {
        ServletRequestAttributes requestAttribute = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletResponse response = requestAttribute.getResponse();

        if (TextUtils.isEmpty(captchaKey)) {
            return;
        }
        try {
            long key = Long.parseLong(captchaKey);
        } catch (Exception e) {
            return;
        }

        // 设置请求头为输出图片类型
        response.setContentType("image/gif");
        response.setHeader("Pragma", "No-cache");
        response.setHeader("Cache-Control", "no-cache");
        response.setDateHeader("Expires", 0);

        // 三个参数分别为宽、高、位数
        SpecCaptcha specCaptcha = new SpecCaptcha(130, 48, 5);
        // 设置字体
        // specCaptcha.setFont(new Font("Verdana", Font.PLAIN, 32));  // 有默认字体，可以不用设置
        specCaptcha.setFont(Captcha.FONT_1);
        // 设置类型，纯数字、纯字母、字母数字混合
        //specCaptcha.setCharType(Captcha.TYPE_ONLY_NUMBER);
        specCaptcha.setCharType(Captcha.TYPE_DEFAULT);

        String content = specCaptcha.text().toLowerCase();
        log.info("captcha content == > " + content);
        // 验证码存入redis
        //request.getSession().setAttribute("captcha", content);
        redisUtils.set(Constans.User.KEY_REDISUTIL_CONTENT + captchaKey, content, 60 * 10);

        specCaptcha.out(response.getOutputStream());

    }

    /*
     *@Author 19145
     *@Description 获取邮箱验证码
     *@Date 20:16 2020/12/29
     *@Param [type(register--->注册,forget----->忘记密码), email]
     *@return com.yujl.response.ResponseResult
     **/
    @Override
    public ResponseResult sendEmail(String type, String email) {
        if (email == null) {
            return ResponseResult.FAILED("邮箱不能为空");
        }

        if ("register".equals(type) || "update".equals(type)) {
            User tbUserByEmail = userDao.findOneByEmail(email);
            if (tbUserByEmail != null) {
                return ResponseResult.FAILED("改邮箱已经注册");
            }
        } else if ("forget".equals(type)) {
            User tbUserByEmail = userDao.findOneByEmail(email);
            if (tbUserByEmail == null) {
                return ResponseResult.FAILED("该邮箱未注册");
            }
        }

        //1、防止暴力发送
        String remoteAddr = getRequest().getRemoteAddr();
        log.info("remoteAddr:------->" + remoteAddr);

        Integer ipSendTime = (Integer) redisUtils.get(Constans.User.KEY_EMAIL_SEND_IP + remoteAddr);
        log.info("ipSendTime------>" + ipSendTime);
        if (ipSendTime != null) {
            if (ipSendTime >= 10) {
                return ResponseResult.FAILED("请不要发送太频繁");
            }
        }

        Object addressSendTime = redisUtils.get(Constans.User.KEY_EMAIL_SEND_ADDRESS + remoteAddr);
        if (addressSendTime != null) {
            return ResponseResult.FAILED("请不要发送太频繁");
        }
        //2、检查邮箱地址是否正确
        if (!TextUtils.isEamilOk(email)) {
            return ResponseResult.FAILED("请输入正确的邮箱");
        }
        //3、发送验证码
        int code = new Random().nextInt(999999);
        if (code <= 100000) {
            code += 100000;
        }
        try {
            EmailSender.sendRegisterVerifyCode(String.valueOf(code), email);
        } catch (Exception e) {
            return ResponseResult.FAILED("发送失败").setData(e.toString());
        }
        //4、记录
        if (ipSendTime == null) {
            ipSendTime = 0;
        }
        ipSendTime++;
        //一个小时有效期
        redisUtils.set(Constans.User.KEY_EMAIL_SEND_IP + remoteAddr, ipSendTime, Constans.TimeValue.HOUR);
        redisUtils.set(Constans.User.KEY_EMAIL_SEND_ADDRESS + remoteAddr, "true", 30);

        //保存code
        redisUtils.set(Constans.User.KEY_EMAIL_CONTENT + email, code, 60 * 10);
        log.info("emailCode------------>" + code);
        return ResponseResult.SUCCESS("发送成功");
    }

    @Override
    public ResponseResult register(User user, String verfiryCode, String captchaCode, String captchaKey) {
        String userName = user.getUsername();
        if (TextUtils.isEmpty(userName)) {
            return ResponseResult.FAILED("用户名不能为空");
        }

        User tbUserByUserName = userDao.findByUsername(userName);
        if (tbUserByUserName != null) {
            return ResponseResult.FAILED("该用户名已注册");
        }

        String email = user.getEmail();
        if (TextUtils.isEmpty(email)) {
            return ResponseResult.FAILED("邮箱不能为空");
        }

        if (!TextUtils.isEamilOk(email)) {
            return ResponseResult.FAILED("邮箱格式错误");
        }

        User tbUserByEmail = userDao.findOneByEmail(email);
        if (tbUserByEmail != null) {
            return ResponseResult.FAILED("该邮箱已注册");
        }

        Integer redisCode = (Integer) redisUtils.get(Constans.User.KEY_EMAIL_CONTENT + email);
        if (TextUtils.isEmpty(String.valueOf(redisCode))) {
            return ResponseResult.FAILED("邮箱验证码过期");
        }
        if (!verfiryCode.equals(String.valueOf(redisCode))) {
            return ResponseResult.FAILED("邮箱验证码错误");
        } else {
            redisUtils.del(Constans.User.KEY_EMAIL_CONTENT + email);
        }

        String redisCaptchaKey = (String) redisUtils.get(Constans.User.KEY_REDISUTIL_CONTENT + captchaKey);
        if (TextUtils.isEmpty(redisCaptchaKey)) {
            return ResponseResult.FAILED("图灵验证码过期");
        }
        if (!captchaCode.equals(redisCaptchaKey)) {
            return ResponseResult.FAILED("图灵验证码错误");
        } else {
            redisUtils.del(Constans.User.KEY_REDISUTIL_CONTENT + captchaKey);
        }

        String password = user.getPassword();
        if (TextUtils.isEmpty(password)) {
            return ResponseResult.FAILED("密码不能为空");
        }
        String salt = ShiroUtil.getRandomSalt();
        String encrypt = ShiroUtil.encrypt(user.getPassword(), salt);
        user.setPassword(encrypt);
        user.setPicture(Constans.User.DEFAULT_AVATAR);
        userDao.save(user);
        return ResponseResult.RGESGIR_SUCCESS();
    }

    @Override
    public ResponseResult doLogin(User user, String captcha, String captchaKey) {
        /*
        1、判断验证码是否正确
        2、判断账号和密码是否为空
        3、查找用户是否存在和对比数据库密码是否错误
        4、密码正确，生成token
         */
        String captchaValue = (String) redisUtils.get(Constans.User.KEY_REDISUTIL_CONTENT + captchaKey);

        if (!captcha.equals(captchaValue)) {
            return ResponseResult.FAILED("图灵验证码不正确");
        }
        redisUtils.del(Constans.User.KEY_REDISUTIL_CONTENT + captchaKey);

        //有可能是邮箱和用户名
        String userName = user.getUsername();
        if (TextUtils.isEmpty(userName)) {
            return ResponseResult.FAILED("账号不可以为空");
        }

        String password = user.getPassword();
        if (TextUtils.isEmpty(password)) {
            return ResponseResult.FAILED("密码不可以为空");
        }

        User tbUser = userDao.findByUsername(userName);
        if (tbUser == null) {
            tbUser = userDao.findOneByEmail(userName);
        }
        if (tbUser == null) {
            return ResponseResult.FAILED("账号或密码错误");
        }
        //用户存在 对比密码

        String encrypt = EncryptUtil.encrypt(password, tbUser.getSalt());
        boolean matches = encrypt.equals(user.getPassword());
        if (matches) {
            return ResponseResult.FAILED("账号或密码错误");
        }
        if ("2".equals(String.valueOf(tbUser.getStatus().intValue()))) {
            return ResponseResult.AUCCOUNT_DENIED();
        }
        //密码正确，生成token
        String tokenKey = creatToken(tbUser);
        return ResponseResult.LOGIN_SUCCESS().setData(tokenKey);
    }

    @Override
    public User checkUser() {
        //拿到tokenKey
        String tokenKey = CookieUtil.getCookie(getRequest(), Constans.User.COOKIE_TOKEN_KEY);
        log.info("tokenKey------->" + tokenKey);
        User user = parseByTokenKey(tokenKey);
        if (user == null) {
            //说明过期了
            //1、去数据库查询refreshtoken
            TbRefreshToken refreshToken = refreshTokenDao.findOneByTokenKey(tokenKey);
            log.info("refreshToken------>" + refreshToken);
            //2、如果不存在，就是没有登录，则提示用户登录
            if (refreshToken == null) {
                return null;
            }
            //3、如果存在就解析refreshToken
            try {
                JwtUtils.parseJWT(refreshToken.getRefreshToken());
                //如果refreshToken有效，则创建新的token和refreshToken
                Long userId = refreshToken.getUserId();
                User userFromDb = userDao.findOneById(userId);
                //删掉refreshToken的记录
                refreshTokenDao.deleteById(refreshToken.getId());
                String newTokenKey = creatToken(userFromDb);
                //返回token
                return parseByTokenKey(newTokenKey);
            } catch (Exception e) {
                //如果refreshToken过期了，提示用户登录
                return null;
            }

        }
        return user;
    }


    @Override
    public ResponseResult checkEmail(String email) {
        User user = userDao.findOneByEmail(email);
        if (user == null) {
            return ResponseResult.FAILED("该邮箱未被注册");
        }
        return ResponseResult.SUCCESS("该邮箱已经被注册");
    }

    @Override
    public ResponseResult checkUserName(String userName) {
        User user = userDao.findOneByUsername(userName);
        if (user == null) {
            return ResponseResult.FAILED("该用户名未被注册");
        }
        return ResponseResult.SUCCESS("该用户名已经被注册");
    }

    @Override
    public ResponseResult updateUserInfo(Long userId, User user) {
        //判断是否登录
        User userFromKey = checkUser();
        if (userFromKey == null) {
            return ResponseResult.AUCCOUNT_NOT_LOGIN();
        }
        User userAccount = userDao.findOneById(userFromKey.getId());
        //判断id是否一致
        log.info("userAccount------>" + userAccount.getId());
        log.info("userId------>" + userId);
        if (!userAccount.getId().equals(userId)) {
            return ResponseResult.AUCCOUNT_UNAUTHORIZED();
        }

        if (!TextUtils.isEmpty(user.getUsername())) {
            User oneByUserName = userDao.findOneByUsername(user.getUsername());
            if (oneByUserName != null) {
                if (!userAccount.getUsername().equals(user.getUsername())) {
                    //如果修改后的用户名与未修改的用户名一致则不提示用户名已经被注册
                    return ResponseResult.FAILED("该用户名已经被注册");
                }
            }
            userAccount.setUsername(user.getUsername());
        }

        //可修改的内容
        if (!TextUtils.isEmpty(user.getPicture())) {
            userAccount.setPicture(user.getPicture());
        }

        userAccount.setUpdateDate(new Date());

        userDao.save(userAccount);

        String tokenKey = CookieUtil.getCookie(getRequest(), Constans.User.COOKIE_TOKEN_KEY);
        redisUtils.del(Constans.User.KEY_TOKEN + tokenKey);
        return ResponseResult.SUCCESS("用户信息更改成功");
    }


    @Override
    public ResponseResult updateUserPassword(String verifyCode, String email, String password) {
        //检查邮箱
        if (TextUtils.isEmpty(email)) {
            return ResponseResult.FAILED("邮箱不可以为空");
        }
        String dbEmail;
        try {
            dbEmail = getDbUser().getEmail();
        } catch (Exception e) {
            return ResponseResult.AUCCOUNT_NOT_LOGIN();
        }

        log.info("dbEmail------>" + dbEmail);
        if (!email.equals(dbEmail)) {
            return ResponseResult.FAILED("邮箱输入错误");
        }

        //根据邮箱去redis拿验证
        Integer redisVerifyCode = (Integer) redisUtils.get(Constans.User.KEY_EMAIL_CONTENT + email);

        if (redisVerifyCode == null || !String.valueOf(redisVerifyCode).equals(verifyCode)) {
            return ResponseResult.FAILED("邮箱验证码错误");
        }
        redisUtils.del(Constans.User.KEY_EMAIL_CONTENT + email);
        String encrypt = EncryptUtil.encrypt(password, getDbUser().getSalt());
        int result = userDao.updatePasswordByEmail(encrypt, email);

        return result > 0 ? ResponseResult.SUCCESS("密码修改成功 ") : ResponseResult.FAILED("密码修改失败");
    }

    @Override
    public ResponseResult updateUserEmail(String verifyCode, String email) {
        User user = checkUser();
        if (user == null) {
            return ResponseResult.AUCCOUNT_NOT_LOGIN();
        }
        String redisVerifyCode = String.valueOf(redisUtils.get(Constans.User.KEY_EMAIL_CONTENT + email));
        if (TextUtils.isEmpty(redisVerifyCode) || !redisVerifyCode.equals(verifyCode)) {
            return ResponseResult.FAILED("验证码错误");
        }
        redisUtils.del(Constans.User.KEY_EMAIL_CONTENT + email);
        int result = userDao.updateEmailById(email, user.getId());

        return result > 0 ? ResponseResult.SUCCESS("邮箱修改成功 ") : ResponseResult.FAILED("邮箱修改失败");
    }

    @Override
    public ResponseResult doLogout() {
        String tokenKey = getRequest().getHeader("Authorization");
        ;
        if (TextUtils.isEmpty(tokenKey)) {
            return ResponseResult.AUCCOUNT_NOT_LOGIN();
        }
        //删除redis
        redisUtils.del(Constans.User.KEY_TOKEN + tokenKey);
        //删除mysql中的refreshToken
        int result = refreshTokenDao.deleteAllByTokenKey(tokenKey);
        CookieUtil.deleteCookie(getResponse(), Constans.User.COOKIE_TOKEN_KEY);
        return ResponseResult.SUCCESS("登出成功");
    }


    private HttpServletRequest getRequest() {
        ServletRequestAttributes requestAttribute = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return requestAttribute.getRequest();
    }

    private HttpServletResponse getResponse() {
        ServletRequestAttributes requestAttribute = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return requestAttribute.getResponse();
    }

    private String creatToken(User tbUser) {
        int resultDelete = refreshTokenDao.deleteAllByUserId(tbUser.getId());
        Map<String, Object> claims = ClaimsUtil.tbUser2Claims(tbUser);
        String token = JwtUtils.createToken(claims);

        //返回token的md5值
        //前端访问的时候，携带token的md5key，从redis中获取即可
        String tokenMd5 = DigestUtils.md5DigestAsHex(token.getBytes());

        //把token写到redis里，有效期两小时
        redisUtils.set(Constans.User.KEY_TOKEN + tokenMd5, token, 2 * Constans.TimeValue.HOUR);

        //把tokenKey写到cookies里去
        //CookieUtil.setUpCookie(response, Constans.User.COOKIE_TOKEN_KEY, tokenMd5);
        //生成refreshtoken
        String refreshTokenValue = JwtUtils.createRefreshToken(String.valueOf(tbUser.getId()), Constans.TimeValue.MONTH);
        //保存到数据库里
        TbRefreshToken refreshToken = new TbRefreshToken();
        refreshToken.setId(idWorker.nextId());
        refreshToken.setRefreshToken(refreshTokenValue);
        refreshToken.setUserId(tbUser.getId());
        refreshToken.setTokenKey(tokenMd5);
        refreshToken.setCreateTime(new Date());
        refreshToken.setUpdateTime(new Date());
        refreshTokenDao.save(refreshToken);
        return tokenMd5;
    }


    private User parseByTokenKey(String tokenKey) {
        String token = (String) redisUtils.get(Constans.User.KEY_TOKEN + tokenKey);
        log.info("token------->" + token);
        if (token != null) {
            try {
                Claims claims = JwtUtils.parseJWT(token);
                return ClaimsUtil.claims2Tbuser(claims);
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    public User getDbUser() {
        String token = JwtUtil.getRequestToken(getRequest());
        log.info("token------>" + token);
        Claims claims = JwtUtils.parseJWT(token);
        return userDao.findByUsername((String) claims.get("userName"));
    }
}
