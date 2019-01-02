package com.sample.service.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

import static com.sample.service.api.AuthErrorResponse.create;

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
                .authenticationEntryPoint((httpServletRequest,httpServletResponse,e) -> {
                    log.debug("Inside custom authentication entry point {}", e);
                    sendResponse(httpServletResponse , e);
                 })
                .jwt();
			// @formatter:on
    }

    private void sendResponse(HttpServletResponse httpServletResponse, AuthenticationException e) {
        httpServletResponse.setContentType("application/json");
        httpServletResponse.setCharacterEncoding("UTF-8");
        httpServletResponse.setStatus(401);

        try {
            PrintWriter out = httpServletResponse.getWriter();
            out.print(objectMapper.writeValueAsString(create(e)));
            out.flush();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}
