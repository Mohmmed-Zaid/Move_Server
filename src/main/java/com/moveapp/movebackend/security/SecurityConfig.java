package com.moveapp.movebackend.security;

import com.moveapp.movebackend.oauth.CustomOAuth2UserService;
import com.moveapp.movebackend.oauth.OAuth2AuthenticationFailureHandler;
import com.moveapp.movebackend.oauth.OAuth2AuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsService userDetailsService;

    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    // ================== Beans ==================

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // ================== Security Filter Chain ==================

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(exception -> exception.authenticationEntryPoint(jwtAuthenticationEntryPoint))
                // IMPORTANT: Change session management for OAuth2
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1))
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints - ORDER MATTERS! More specific patterns should come first

                        // OTP endpoints (most specific first)
                        .requestMatchers(
                                "/api/otp/send",
                                "/api/otp/verify",
                                "/api/otp/verify-signup-otp",
                                "/api/otp/signup-with-otp",
                                "/api/otp/status/**",
                                "/api/otp/debug/**"
                        ).permitAll()

                        // All OTP endpoints
                        .requestMatchers("/api/otp/**").permitAll()

                        // Auth endpoints (all public for authentication)
                        .requestMatchers(
                                "/api/auth/signup",
                                "/api/auth/signup/**",
                                "/api/auth/signin",
                                "/api/auth/login",
                                "/api/auth/otp/**",
                                "/api/auth/send-signup-otp",
                                "/api/auth/send-password-reset-otp",
                                "/api/auth/password/**",
                                "/api/auth/password/reset",
                                "/api/auth/validate",
                                "/api/auth/test",
                                "/api/auth/refresh",
                                "/api/auth/signout"
                        ).permitAll()

                        // OAuth2 endpoints - CRITICAL: These must be public
                        .requestMatchers(
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/api/oauth2/**"
                        ).permitAll()

                        // Public API endpoints
                        .requestMatchers("/api/public/**").permitAll()

                        // Debug endpoints
                        .requestMatchers("/api/debug/**").permitAll()

                        // External service endpoints (public)
                        .requestMatchers("/api/geocoding/**").permitAll()
                        .requestMatchers(
                                "/api/routes/calculate",
                                "/api/routes/user",
                                "/api/routes/*/favorite",
                                "/api/routes/*",
                                "/api/routes/save"
                        ).permitAll() // Made public for testing - change to authenticated() for production

                        // Location endpoints (require authentication)
                        .requestMatchers("/api/locations/**").authenticated()

                        // Navigation endpoints (require authentication)
                        .requestMatchers("/api/navigation/**").authenticated()

                        // Documentation endpoints
                        .requestMatchers(
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html"
                        ).permitAll()

                        // Health check endpoints
                        .requestMatchers("/actuator/health", "/health").permitAll()

                        // Static resources and error pages
                        .requestMatchers(
                                "/ws/**",
                                "/error",
                                "/favicon.ico",
                                "/.well-known/**"
                        ).permitAll()

                        // All other endpoints require authentication
                        .anyRequest().authenticated()
                )
                // OAuth2 Login Config - FIXED
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authz -> authz.baseUri("/oauth2/authorization"))
                        .redirectionEndpoint(redirection -> redirection.baseUri("/login/oauth2/code/*"))
                        .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler)
                        .permitAll() // IMPORTANT: Allow OAuth2 endpoints
                );

        // Use custom authentication provider + JWT filter
        http.authenticationProvider(authenticationProvider());
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ================== CORS Config ==================

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allow specific origins (more secure than using "*")
        configuration.setAllowedOriginPatterns(Arrays.asList(
                "http://localhost:3000",    // React dev
                "http://localhost:5173",    // Vite dev
                "http://localhost:5137",    // Your actual frontend port
                "http://127.0.0.1:3000",   // Alternative localhost
                "http://127.0.0.1:5173",   // Alternative localhost
                "http://127.0.0.1:5137",   // Your actual frontend port
                "https://yourdomain.com"    // Production domain
        ));

        // Allow all HTTP methods that you use
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"
        ));

        // Allow all headers
        configuration.setAllowedHeaders(Arrays.asList("*"));

        // Allow credentials (important for authentication)
        configuration.setAllowCredentials(true);

        // Cache preflight requests for 1 hour
        configuration.setMaxAge(3600L);

        // Expose headers that frontend might need
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}