package com.example.authz.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Authentication only. Authorization decisions are made by Casbin (see AuthorizationService).
 *
 * HTTP Basic with in-memory users keeps the sample self-contained; swap the
 * UserDetailsService for LDAP / OIDC resource-server config in production. The only
 * contract the rest of the service relies on is that the authenticated principal carries
 * granted authorities of the form ROLE_&lt;NAME&gt;.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("alice").password("{noop}password").roles("ADMIN").build(),
                User.withUsername("bob").password("{noop}password").roles("EDITOR").build(),
                User.withUsername("carol").password("{noop}password").roles("VIEWER").build(),
                User.withUsername("dave").password("{noop}password").roles("AUDITOR", "CONTRACTOR").build(),
                User.withUsername("erin").password("{noop}password").roles("APPROVER").build()
        );
    }
}
