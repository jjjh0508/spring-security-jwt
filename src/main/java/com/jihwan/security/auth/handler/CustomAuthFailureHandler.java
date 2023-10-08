package com.jihwan.security.auth.handler;

import org.json.simple.JSONObject;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

public class CustomAuthFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        JSONObject jsonObject;
        String failMsg;

        if(exception instanceof AuthenticationServiceException){
            failMsg = "존재하지 않는 사용자 입니다.";
        }else if(exception instanceof BadCredentialsException){
            failMsg = "아이디 또는 비밀번호가 틀립니다.";
        }else if(exception instanceof LockedException){
            failMsg = "잠긴 계정입니다.";
        } else if (exception instanceof DisabledException) {
            failMsg = "비활성화된 계정입니다.";
        } else if (exception instanceof AccountExpiredException) {
            failMsg = "만료된 계정입니다.";
        } else if (exception instanceof CredentialsExpiredException) {
            failMsg = "비밀번호가 만료됐습니다.";
        }else {
            failMsg = "정의되있는 케이스의 오류가 아닙니다.";
        }
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();

        HashMap<String , Object>  resultMap = new HashMap<>();

        resultMap.put("failType" , failMsg);

        jsonObject = new JSONObject(resultMap);

        printWriter.println(jsonObject);
        printWriter.flush();
        printWriter.close();

    }
}
