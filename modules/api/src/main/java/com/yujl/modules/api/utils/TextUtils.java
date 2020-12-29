package com.yujl.modules.api.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TextUtils {

    private static final String regEx = "^([a-z0-9A-Z]+[-|\\.]?)+[a-z0-9A-Z]@([a-z0-9A-Z]+(-[a-z0-9A-Z]+)?\\.)+[a-zA-Z]{2,}$";

    public static boolean isEmpty(String text){
        return text==null || text.length()==0;
    }

    public static boolean isEamilOk(String email){
        Pattern p = Pattern.compile(regEx);
        Matcher m = p.matcher(email);
        return m.matches();
    }
}
