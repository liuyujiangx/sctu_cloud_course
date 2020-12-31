package com.yujl.common.utils;

public interface Constans {

    int DEFAULT_SIZE = 30;

    interface User {
        String ROLE_ADMIN = "role_admin";
        String ROLE_NORMAL = "role_normal";
        String DEFAULT_AVATAR = "https://dss0.bdstatic.com/70cFvHSh_Q1YnxGkpoWK1HF6hhy/it/u=2856846879,389279115&fm=26&gp=0.jpg";
        String DEFAULT_STATE = "1";
        String KEY_REDISUTIL_CONTENT = "KEY_REDISUTIL_CONTENT_";
        String KEY_EMAIL_CONTENT = "KEY_EMAIL_CONTENT";
        String KEY_EMAIL_SEND_IP = "key_email_send_ip";
        String KEY_EMAIL_SEND_ADDRESS = "key_email_send_address";
        String KEY_TOKEN = "key_token";
        String COOKIE_TOKEN_KEY = "yujl_blog_token";
    }

    interface Setting {
        String MANAGER_ACCOUNT_INIT_STATE = "MANAGER_ACCOUNT_INIT_STATE";
    }

    interface TimeValue {
        int MIN = 60;
        int HOUR = 60 * MIN;
        int DAY = 24 * HOUR;
        int WEEK = 7 * DAY;
        int MONTH = 30 * DAY;
        int YEAR = 12 * MONTH;
    }
}
