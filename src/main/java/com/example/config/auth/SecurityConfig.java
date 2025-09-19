package com.example.config.auth;

import com.example.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.frameOptions(frame -> frame.disable()))

                .authorizeHttpRequests(auth -> auth
                        // 정적 리소스( /css, /js, /images, /webjars 등 ) 모두 허용
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                        // 루트와 H2 콘솔 허용
                        .requestMatchers("/", "/h2-console/**").permitAll()
                        // API 는 ROLE_USER 만 접근 (Enum Role.USER -> "ROLE_USER" 로 매핑됨)
                        .requestMatchers("/api/v1/**").hasRole(Role.USER.name())
                        // 나머지는 인증 필요
                        .anyRequest().authenticated()
                )

                /* ── 세션 정책: 기본(Form/OAuth2)이라 필요 시 세션 생성 ──────────────── */
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )

                /* ── 로그아웃 ──────────────────────────────────────────────────────── */
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                )

                /* ── OAuth2 로그인 + 커스텀 유저서비스 ─────────────────────────────── */
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                        // 필요 시 기본 로그인 페이지 사용
                        .loginPage("/oauth2/authorization/google")
                        .defaultSuccessUrl("/",true)
                )

                /* ── CORS 필요 시 (프론트 별도 도메인일 때) ─────────────────────────── */
                .cors(Customizer.withDefaults());

        return http.build();
    }

    /* 패스워드 인코더 (필요 시) — 소셜 로그인 외에 폼로그인/회원가입 쓸 때 */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}