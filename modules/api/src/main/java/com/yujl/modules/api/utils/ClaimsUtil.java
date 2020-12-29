package com.yujl.modules.api.utils;

import com.yujl.modules.system.domain.Role;
import com.yujl.modules.system.domain.User;
import io.jsonwebtoken.Claims;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class ClaimsUtil {

    private static final String ID = "id";
    private static final String USERNAME = "userName";
    private static final String ROLES = "roles";
    private static final String AVATAR = "avatar";
    private static final String EMAIL = "email";

    public static Map<String, Object> tbUser2Claims(User tbUser) {
        Map<String, Object> claims = new HashMap<>();

        claims.put(ID, tbUser.getId());
        claims.put(USERNAME, tbUser.getUsername());
        claims.put(ROLES, tbUser.getRoles());
        claims.put(AVATAR, tbUser.getPicture());
        claims.put(EMAIL, tbUser.getEmail());
        return claims;
    }

    public static User claims2Tbuser(Claims claims) {
        User user = new User();
        user.setId((Long) claims.get(ID));
        user.setRoles((Set<Role>) claims.get(ROLES));
        user.setUsername((String) claims.get(USERNAME));
        user.setPicture((String) claims.get(AVATAR));
        user.setEmail((String) claims.get(EMAIL));

        return user;
    }
}
