package com.example.search;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration. /api/search is intentionally in the permitAll()
 * whitelist — this is what makes the SearchController vulnerability reachable
 * without authentication (a fact the Validator should verify).
 */
@Configuration
public class SecurityConfig {

    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(r -> r
                .requestMatchers("/api/search").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
