package com.sample.service.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final ObjectMapper objectMapper;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
		http
			.logout()
        .and()
			.authorizeRequests()
				.anyRequest()
                .authenticated()
        .and()
            .oauth2ResourceServer()
                .jwt();
			// @formatter:on
    }

}
