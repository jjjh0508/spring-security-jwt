package com.jihwan.security.common.utils;


import com.jihwan.security.user.entity.User;
import io.jsonwebtoken.*;
import org.hibernate.type.DateType;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

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


    /**
     * token을 생성하는 메서드
     * @param user - userEntity
     * @return   String - token
     * */
    public static String generateJwtToken(User user) {
        Date expireTime = new Date(System.currentTimeMillis()+tokenValidateTime);
        JwtBuilder builder = Jwts.builder()
                .setHeader(createHeader())     // 헤더 설정
                .setClaims(createClaims(user)) // 크레임 추가
                .setSubject("ohgiraffers token : "+user.getUserNo())  // 토큰의 제목
                .signWith(SignatureAlgorithm.HS256,createSignature()) // 토큰 생성
                .setExpiration(expireTime); // 토큰 유효시간

        return builder.compact();
    }


    /**
     * token의 header를 설정하는 메서드
     * @return Map<String, Object > - header의 설정 정보
     *
     * */
    private static Map<String,Object> createHeader(){
        Map<String ,Object> header = new HashMap<>();
        header.put("type","jwt");
        header.put("alg","HS256");
        header.put("date",System.currentTimeMillis());

        return header;

    }

    /**
     * 사용자 정보를 기반으로 클레임을 성성해주는 메서드
     *
     * @param user - 사용자 정보
     * @return Map<String , object> claims 정보
     * */

    private static Map<String , Object> createClaims(User user){
        Map<String , Object> claims = new HashMap<>(); // 사용자의 정보를 담는 부분 (페이로드)

        claims.put("userName", user.getUserName());
        claims.put("Role",user.getRole());
        claims.put("userEmail",user.getUserEmail());

        return claims;

    }

    /**
     * JWT 서명을 발급해주는 메서드이다.
     *
     * @return key
     *
     * */

    private static Key createSignature(){
        byte[] secretBytes = DatatypeConverter.parseBase64Binary(jwtSecretkey);
        return new SecretKeySpec(secretBytes, SignatureAlgorithm.HS256.getJcaName());
    }
}


