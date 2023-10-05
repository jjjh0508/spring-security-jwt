package com.jihwan.security.auth.filter;


import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
* cors 설정을 위한 fiter 설정
* */

public class HeaderFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse) response;
        res.setHeader("Access-Control-Allow-Origin", "*"); //다른 외부 요청의 응답을 허용 할 것인가?
        res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE"); //외부 요청에 허용할 메소드
        res.setHeader("Access-Control-Max-Age","3600"); // 캐싱을 허용할 시간
        res.setHeader("Access-Control-Allow-Headers","X-Requested-With,Content-Type, Authorization,X-XSRF-token");
                        //
        res.setHeader("Access-Control-Allow-Credentials","false"); // 자격증명
        chain.doFilter(request,response);


    }
}
