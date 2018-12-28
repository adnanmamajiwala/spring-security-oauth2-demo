package com.sample.auth.configurations;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

@Configuration
@EnableAuthorizationServer
@RequiredArgsConstructor
public class OAuth2ServerConfiguration extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;
    private final BCryptPasswordEncoder passwordEncoder;
    private final TokenStore tokenStore;
    private final JwtAccessTokenConverter jwtAccessTokenConverter;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // @formatter:off
		clients.inMemory()
            .withClient("acme")
                .secret(passwordEncoder.encode("acmesecret"))
                .authorizedGrantTypes("authorization_code", "refresh_token")
                .scopes("openid")
                .accessTokenValiditySeconds(2 * 60 * 60)
                .and()
            .withClient("public-call")
                .secret(passwordEncoder.encode("public"))
                .authorizedGrantTypes("password", "refresh_token")
                .scopes("openid")
                .accessTokenValiditySeconds(60 * 60)
                .refreshTokenValiditySeconds(2 * 60 * 60);
		// @formatter:on
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        // @formatter:off
		endpoints
			.authenticationManager(this.authenticationManager)
			.accessTokenConverter(jwtAccessTokenConverter)
			.tokenStore(tokenStore)
//            .exceptionTranslator(this::oAuth2ExceptionResponseEntity)
            ;
		// @formatter:on
    }

    private ResponseEntity<OAuth2Exception> oAuth2ExceptionResponseEntity(Exception e) throws Exception {
        ObjectWriter writer = new ObjectMapper().writerWithDefaultPrettyPrinter();
        System.out.println("-----------------------------");
        System.out.println(writer.writeValueAsString(e));
        System.out.println("-----------------------------");
        if (e instanceof OAuth2Exception) {
            OAuth2Exception oAuth2Exception = (OAuth2Exception) e;
            return ResponseEntity
                    .status(oAuth2Exception.getHttpErrorCode())
                    .body(new CustomOAuth2Exception(oAuth2Exception.getMessage()));
        } else {
            throw e;
        }
    }


}
