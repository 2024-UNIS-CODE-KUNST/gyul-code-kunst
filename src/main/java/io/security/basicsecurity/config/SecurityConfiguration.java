package io.security.basicsecurity.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.sql.DataSource;
import java.io.IOException;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {
    @Bean
    public UserDetailsService userDetailsService() {
        // 기본 사용자 및 비밀번호 설정
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { // 사용자 정의 보안 기능
        // 1. 기본 설정
        http
                .authorizeHttpRequests((auths) -> auths
                        .anyRequest().authenticated()
                );
        // 2. 로그인 설정
        http
                .formLogin(
                        formLogin ->
                                formLogin
                                        .defaultSuccessUrl("/")
                                        .failureUrl("/login")
                                        .usernameParameter("userId")
                                        .passwordParameter("pwd")
                                        .loginProcessingUrl("/login_proc") // login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행
                                        .successHandler(new AuthenticationSuccessHandler() {
                                            @Override
                                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                                System.out.println("authentication: " + authentication.getName());
                                                response.sendRedirect("/");
                                            }
                                        })
                                        .failureHandler(new AuthenticationFailureHandler() {
                                            @Override
                                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                                System.out.println("exception" + exception.getMessage());
                                                response.sendRedirect("/loginPage");
                                            }
                                        })
                                        .permitAll() // loginForm으로는 인증받지 않아도 접근 가능하도록
                );
        // 3. 로그아웃 설정: 원칙적으로 Post 방식으로 처리해야 함
        http
                .logout(
                        logoutConfig ->
                                logoutConfig
                                        .logoutUrl("/logout") // 로그아웃 Url
                                        .logoutSuccessUrl("/login") // 로그아웃 성공 시 리다이렉트 페이지
                                        .deleteCookies("remember-me") // 쿠키 삭제
                                        .addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러: 세션 무효화 + 쿠키 삭제 외의 별도로 처리하고 싶을 경우
                                            @Override
                                            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                                HttpSession session = request.getSession();
                                                session.invalidate(); // 세션 무효화
                                            }
                                        })
                                        .logoutSuccessHandler(new LogoutSuccessHandler() { // 로그아웃 성공 핸들러: 별도로 처리하고 싶을 경우
                                            @Override
                                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                                response.sendRedirect("/login"); // 로그인 페이지로 리다이렉트
                                            }
                                        })
                );
        // 4. remember me
        http
                .rememberMe(
                        rememberMeConfig ->
                                rememberMeConfig
                                        .rememberMeParameter("remember")
                                        .tokenValiditySeconds(3600) // 기본 14일
                                        .alwaysRemember(false) // 항상 기억하기 (기본적으로 False 설정 해줄 것)
                                        .userDetailsService(userDetailsService())
                );
        // remember me 설정 없이 로그인하면 쿠키 삭제했을 경우에 메인페이지 접근이 안 됨. 왜냐하면 쿠키에 있는 세션아이디랑 로그인할 때 가지고 있던 세션아이디를 비교해서 처리하는 거라...
        // 5. 세션 제어
        http
                .sessionManagement(
                        sessionManagementConfig -> // 전반적인 세션 관리 설정을 위한 세부적인 옵션
                                sessionManagementConfig
                                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                                        .sessionFixation().changeSessionId()
                                        .maximumSessions(100)
                                        .maxSessionsPreventsLogin(true)
                                        .expiredUrl("/expired")
                )
                .sessionManagement(
                        session -> // 세션 관리 설정의 일반적인 부분
                                session
                                        .invalidSessionUrl("/invalid")
                                        .sessionFixation().newSession()
                );
        // 기타
        http
                .httpBasic(withDefaults());


        return http.build();
    }
}
