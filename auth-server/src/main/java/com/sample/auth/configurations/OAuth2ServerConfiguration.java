package com.sample.auth.configurations;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.security.KeyPair;

@Configuration
@EnableAuthorizationServer
@RequiredArgsConstructor
public class OAuth2ServerConfiguration extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;
    private final BCryptPasswordEncoder passwordEncoder;
    private final KeyPair keyPair;
    private final OAuthExceptionBuilder exceptionBuilder;

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
        JwtAccessTokenConverter accessTokenConverter = jwtAccessTokenConverter();
        endpoints
                .authenticationManager(this.authenticationManager)
                .accessTokenConverter(accessTokenConverter)
                .tokenStore(new JwtTokenStore(accessTokenConverter))
                .exceptionTranslator(this::oAuth2ExceptionResponseEntity);
    }

    private ResponseEntity<OAuth2Exception> oAuth2ExceptionResponseEntity(Exception e) throws Exception {
        OAuth2Exception oAuth2Exception = exceptionBuilder.build(e);
        return ResponseEntity
                .status(oAuth2Exception.getHttpErrorCode())
                .body(oAuth2Exception);
    }

    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setKeyPair(keyPair);

        DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
        accessTokenConverter.setUserTokenConverter(new ApplicationWebSecurityConfiguration.CustomTokenConverter());
        converter.setAccessTokenConverter(accessTokenConverter);
        return converter;
    }

}
