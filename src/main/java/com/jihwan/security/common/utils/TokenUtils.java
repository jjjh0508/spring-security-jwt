package com.jihwan.security.common.utils;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;

import javax.xml.bind.DatatypeConverter;

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

    /**
     * header의 token을 분리하는 메소드
     * @param header : Authorization의 header 값을 가져온다.
     * @return token : Authorization 의 token 부분을 반환한다.
     * */

    public static String splitHeader(String header){
        if(!header.equals("")){
            return header.split(" ")[1];
        }else {
            return null;
        }
    }


    /**
     * 유효한 토근인지 확인하는 메서드
     * @param token : 토큰
     * @return boolean : 유효 여부
     * @throws  : ExpiredJwtException ,JwtException, NullPointerException
     * */

    public static boolean isValidToken(String token){
        try {
            Claims claims = getClaimsFromToken(token);
            return true;

        }catch (ExpiredJwtException e){
            e.printStackTrace();
            return false;
        }catch (JwtException e){
            e.printStackTrace();
            return false;
        }catch (NullPointerException e){
            e.printStackTrace();
            return false;
        }

    }


    /**
     * 토큰을 복화하는 메서드
     * @param token
     * @return Claims
     *
     * */
    public static Claims getClaimsFromToken(String token){
        return Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecretkey))
                .parseClaimsJws(token).getBody();
    }
}


