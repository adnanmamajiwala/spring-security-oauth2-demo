package com.sample.auth.configurations;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Configuration
@RequiredArgsConstructor
@EnableResourceServer
public class ApplicationWebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final BCryptPasswordEncoder passwordEncoder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS, "/oauth/token").permitAll()
                .mvcMatchers("/.well-known/jwks.json").permitAll()
                .anyRequest().authenticated()
                .and()
                .exceptionHandling()
                .accessDeniedHandler(this::getAccessDeniedHandler);
    }

    private void getAccessDeniedHandler(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AccessDeniedException exception) throws JsonProcessingException {
        ObjectWriter writer = new ObjectMapper().writerWithDefaultPrettyPrinter();
        System.out.println("-----------------------------");
        System.out.println(writer.writeValueAsString(exception));
        System.out.println("-----------------------------");
    }

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder.encode("pass"))
                .roles("USER")
            .and()
                .withUser("admin")
                .password(passwordEncoder.encode("nimda"))
                .roles("ADMIN");
    }

//    @Bean
//    @Override
//    public UserDetailsService userDetailsService() {
//        UserDetails user1 = User.builder()
//                .username("user")
//                .password(passwordEncoder.encode("pass"))
//                .roles("USER")
//                .build();
//        UserDetails user2 = User.builder()
//                .username("admin")
//                .password(passwordEncoder.encode("nimda"))
//                .roles("ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(user1, user2);
//    }


}
