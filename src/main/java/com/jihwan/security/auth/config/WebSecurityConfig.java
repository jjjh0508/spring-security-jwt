package com.jihwan.security.auth.config;


import com.jihwan.security.auth.filter.CustomAuthenticationFilter;

import com.jihwan.security.auth.filter.JwtAuthorizationFilter;
import com.jihwan.security.auth.handler.CustomAuthFailureHandler;

import com.jihwan.security.auth.handler.CustomAuthLoginSuccessHandler;
import com.jihwan.security.auth.handler.CustomAuthenticationProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class WebSecurityConfig {
    /**
     * 1. 정적 자원에 대한 인증된 사용자의 접근을 설정하는 메소드
     *
     * @return WebSecurityCusomizer
     */

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    /**
     * security filter chain 설정
     *
     * @return SecurityFilterChain
     */

    //antMatchers 특정 리소스에 대해서 권한을 설정 /  특정 경로를 지정합니다.
    //anyRequest  모든 리로스를 의미하며 접근 허용 리소스 및 인증 후 특정 레벨의 권한을 가진 사용자만 접근 가능한 리소르를 설정한 수에 사용
    //그 외 나머지 리소스들에 대한 접근 허용 수준을 결정할때 사용 / 설정한 경로 외에 모든 경로를 뜻
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //Cross Site Request Forgery 위조 공격
        //  http.csrf().disable() 세션 기반이 아닌 토큰 기반 인증에서는 disable 처리해서 사용하지 않는다
        http.csrf().disable()
                //프레임 설정(X-Frame  iframe 같은 )   sameOrigin 설정 -> 동일한 도메인에서  제공되는 프레임만 보여주곘다
                //allow-from url 지정된 url일 경우에만 frame에 화면을 띄울수 있다
                //DENY 어떤 url이 오더라고 Frame에 화면을 띄우지 않게 설정
                //disable  모든 프레임을 허용
                .headers(header -> header.frameOptions().sameOrigin())
                .authorizeRequests()
//                .antMatchers("/test").hasAnyRole("USER")
                // 권한을 직접적으로 줄 수 있지만 -> @EnableGlobalMethodSecurity(prePostEnabled = true) 메소드로 설정
                .anyRequest().permitAll()  // 모든 요청을 허용한다
                .and()
                //필터
                .addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //토큰기반 인증 이기때문에 세션을 사용하지 않겠다
                .and()
                .formLogin().disable() // 로그인폼 사용하지 않음
                .addFilterBefore(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                // UsernamePasswordAuthenticationFilter란 Form based Authentication 방식으로 인증을 진행할 때 아이디, 패스워드 데이터를 파싱하여 인증 요청을 위임하는 필터이다.

                .httpBasic().disable();

        return http.build();
    }


    /**
     * 3. Authorization의  인증 메서드를 제공하는 매니저로 Provider의 인터페이스를 의미한다.
     *
     * @return AuthenticationManager
     */

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(customAuthenticationProvider());
    }

    /**
     * 4. 사용자의 아이디와 패스워드를 DB와 검증하는 handler 이다.
     *
     * @return CustomAuthenticationProvider
     */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }


    /**
     * 5. 비밀번호를 암호하는 인코더
     *
     * @return BCryptPasswordEncoder
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * 6. 사용자의 인증 요청을 가로채서 로그인 로직을 수행하는 필터
     *
     * @return CustomAuthenticationFilter
     */


    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter() {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager());
        customAuthenticationFilter.setFilterProcessesUrl("/login");  //로그인 요청
        customAuthenticationFilter.setAuthenticationSuccessHandler(customAuthSuccessHandler());
        customAuthenticationFilter.setAuthenticationFailureHandler(customAuthFailureHandler());
        customAuthenticationFilter.afterPropertiesSet();

        return customAuthenticationFilter;

    }


    /**
     * 7. spring security 기반의 사용지의 정보가 맞을 경우 결과를 수행하는 handler
     *
     * @return customAuthLoginSuccessHandler
     */

    @Bean
    public CustomAuthLoginSuccessHandler customAuthSuccessHandler() {
        return new CustomAuthLoginSuccessHandler();
    }


    /**
     * 8. Spring security의 사용자 정보가 맞지 않는 경우 실행되는 메서드
     *
     * @return CustomAuthFailureHandler
     * */


    @Bean
    public CustomAuthFailureHandler customAuthFailureHandler(){
        return new CustomAuthFailureHandler();

    }


    /**
     * 9. 사용자 요청시 수행되는 메소드
     * @return JwtAutharizationFilter
     * */

    public JwtAuthorizationFilter jwtAuthorizationFilter (){

        return  new JwtAuthorizationFilter(authenticationManager());
    }
}
