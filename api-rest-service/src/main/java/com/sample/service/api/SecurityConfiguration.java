package com.sample.service.api;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

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
            .oauth2ResourceServer().jwt();
			// @formatter:on
    }
}
