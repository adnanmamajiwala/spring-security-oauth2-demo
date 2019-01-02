package com.sample.service.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import java.util.Objects;

import static org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes.INVALID_REQUEST;
import static org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes.INVALID_TOKEN;

@Data
public class AuthErrorResponse {

    private String error;

    @JsonProperty("error_code")
    private String code;

    @JsonProperty("error_description")
    private String description;

    public AuthErrorResponse(String error, String description) {
        this.error = error;
        this.description = description;
    }

    public static AuthErrorResponse create(AuthenticationException e) {
        String description = Objects.isNull(e) ? "oAuth_error" : e.getMessage();
        String error = "oAuth_error";

        if (e instanceof OAuth2AuthenticationException) {
            OAuth2AuthenticationException ex = (OAuth2AuthenticationException) e;
            description = ex.getError().getDescription();
            error = ex.getError().getErrorCode();
        }

        AuthErrorResponse authErrorResponse = new AuthErrorResponse(error, description);

        if (INVALID_TOKEN.equals(error)) {
            authErrorResponse.setCode("2001");
        } else if (INVALID_REQUEST.equals(error)) {
            authErrorResponse.setCode("2002");
        } else {
            authErrorResponse.setCode("2099");
        }

        return authErrorResponse;
    }

}
