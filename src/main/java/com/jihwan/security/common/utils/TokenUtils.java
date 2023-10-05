package com.jihwan.security.common.utils;


import org.springframework.beans.factory.annotation.Value;

/**
 * 토큰을 관리하기 위한 utils 모음 클래스
 * yml -> jwt-key , jwt-time 설정이 필요하다
 * jwt lib 버전은 io.jsonwebtoken:jjwt:0.9.1
 *
 * */
public class TokenUtils {

    private static  String jwtSecretkey;
    public  static  Long tokenValidateTime;

    @Value("${jwt.key}")
    public  void setJwtSecretkey(String jwtSecretkey) {
        TokenUtils.jwtSecretkey = jwtSecretkey;
    }


    @Value("${jwt.time}")
    public  void setTokenValidateTime(Long tokenValidateTime) {
        TokenUtils.tokenValidateTime = tokenValidateTime;
    }
}


