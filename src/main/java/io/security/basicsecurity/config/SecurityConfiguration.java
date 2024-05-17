package io.security.basicsecurity.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { // 사용자 정의 보안 기능
        http
                .authorizeHttpRequests((auths) -> auths
                        .anyRequest().authenticated()
                )
                .formLogin(
                        formLogin ->
                                formLogin
                                        .loginPage("/loginPage")
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
                )
                .httpBasic(withDefaults());
        return http.build();
    }
}
