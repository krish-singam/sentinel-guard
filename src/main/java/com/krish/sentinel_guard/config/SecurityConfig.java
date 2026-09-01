package com.krish.sentinel_guard.config;

import com.krish.sentinel_guard.waf.filter.WafTrafficInspectionFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final WafTrafficInspectionFilter wafTrafficInspectionFilter;

    public SecurityConfig(WafTrafficInspectionFilter wafTrafficInspectionFilter) {
        this.wafTrafficInspectionFilter = wafTrafficInspectionFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails superAdmin = User.builder()
                .username("krishna")
                .password(encoder.encode("krishna"))
                .roles("SUPER_ADMIN", "SECURITY_ANALYST", "AUDITOR")
                .build();

        UserDetails securityAnalyst = User.builder()
                .username("alex")
                .password(encoder.encode("alex"))
                .roles("SECURITY_ANALYST", "AUDITOR")
                .build();

        UserDetails auditor = User.builder()
                .username("sarah")
                .password(encoder.encode("sarah"))
                .roles("AUDITOR")
                .build();

        return new InMemoryUserDetailsManager(superAdmin, securityAnalyst, auditor);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
            .addFilterBefore(wafTrafficInspectionFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth
                // Static resources & public endpoints
                .requestMatchers(
                    "/", "/index.html", "/favicon.ico", "/css/**", "/js/**", "/images/**",
                    "/h2-console/**", "/api/auth/status", "/api/auth/roles", "/api/auth/logout",
                    "/api/traffic/**", "/gateway/**", "/ws/**"
                ).permitAll()
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // RBAC: Red-Team Attack Simulation is strictly SUPER_ADMIN
                .requestMatchers("/api/simulation/**").hasRole("SUPER_ADMIN")

                // RBAC: Domain Management (Add/Delete) & IP Ban controls
                .requestMatchers(HttpMethod.POST, "/api/domains/**").hasAnyRole("SUPER_ADMIN", "SECURITY_ANALYST")
                .requestMatchers(HttpMethod.DELETE, "/api/domains/**").hasRole("SUPER_ADMIN")
                .requestMatchers("/api/firewall/**").hasAnyRole("SUPER_ADMIN", "SECURITY_ANALYST")

                // Authenticated general endpoints (Basic Auth)
                .requestMatchers("/api/auth/login", "/api/auth/me", "/api/dashboard/**", "/api/domains/**", "/api/incidents/**", "/api/reports/**", "/api/audit/**").authenticated()

                .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}

