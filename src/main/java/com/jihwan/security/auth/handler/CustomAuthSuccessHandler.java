package com.jihwan.security.auth.handler;

import com.jihwan.security.auth.model.DetailsUser;
import com.jihwan.security.common.Authconstants;
import com.jihwan.security.common.utils.ConvertUtil;
import com.jihwan.security.common.utils.TokenUtils;
import com.jihwan.security.user.entity.User;
import org.json.simple.JSONObject;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Objects;


@Configuration
public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        User user = ((DetailsUser) authentication.getPrincipal()).getUser();
        JSONObject jsonValue = (JSONObject) ConvertUtil.convertObjectJsonObject(user);
        HashMap<String , Object> responseMap = new HashMap<>();
        JSONObject jsonObject;
        if(user.getState().equals("N")){
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "휴면상태인 계정입니다.");
        }else {
            String token = TokenUtils.generateJwtToken(user);
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message","로그인 성공");

            response.addHeader(Authconstants.AUTH_HEADER,Authconstants.TOKEN_TYPE +" "+token);

        }

        jsonObject = new JSONObject(responseMap);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");

        PrintWriter printWriter = response.getWriter();
        printWriter.println(jsonObject);
        printWriter.flush();
        printWriter.close();


    }

}
