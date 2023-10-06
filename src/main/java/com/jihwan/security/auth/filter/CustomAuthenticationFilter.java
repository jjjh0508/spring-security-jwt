package com.jihwan.security.auth.filter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jihwan.security.auth.model.dto.LoginDto;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }


    /**
     * 지정된 url 요청시 해당 요청을 가로채서 검증 로직을 수행하는 메서드
     *
     * */

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authenticationToken;
        try {
            authenticationToken = getAuthRequest(request);
            setDetails(request,authenticationToken);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


        return this.getAuthenticationManager().authenticate(authenticationToken);
    }



    /**
     * 사용자의 로그인 리소스 요청시 요청 정보를 임시 토큰에 저장하는 메서드
     *
     * @param request  - HttpServletRequest
     * @return UserpasswordAuthenticationToken
     * @throw Excpetion e
     * */

    private UsernamePasswordAuthenticationToken getAuthRequest(HttpServletRequest request) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        /*
         * json 요청을 자바 object로 매핑하거나 json 형식으로 직렬화 하는데
         * 사용되는 리소스를 자동으로 닫도록 설정
         *
         * */

        objectMapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE,true);

        LoginDto user  = objectMapper.readValue(request.getInputStream(), LoginDto.class);

        return new UsernamePasswordAuthenticationToken(user.getId(),user.getPass());


    }
}
