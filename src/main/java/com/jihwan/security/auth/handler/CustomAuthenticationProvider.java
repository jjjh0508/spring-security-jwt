package com.jihwan.security.auth.handler;

import com.jihwan.security.auth.model.DetailsUser;
import com.jihwan.security.auth.service.DetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private DetailsService detailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken loginToken  = (UsernamePasswordAuthenticationToken)  authentication;
        String id = loginToken.getName();
        String pass = (String)  loginToken.getCredentials(); // 패스워드

        DetailsUser detailsUser = (DetailsUser)  detailsService.loadUserByUsername(id);

        if(!passwordEncoder.matches(pass, detailsUser.getPassword())){
            throw  new BadCredentialsException(pass + "는 비밀번호가 아닙니다.");
        }
        return new UsernamePasswordAuthenticationToken(detailsUser,pass,detailsUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {

        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
