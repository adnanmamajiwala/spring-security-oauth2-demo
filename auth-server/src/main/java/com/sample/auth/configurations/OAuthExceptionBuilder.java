package com.sample.auth.configurations;

import org.springframework.security.oauth2.common.exceptions.*;
import org.springframework.stereotype.Component;

import static org.springframework.security.oauth2.common.exceptions.OAuth2Exception.*;

@Component
public class OAuthExceptionBuilder {

    public OAuth2Exception build(Exception e) {
        OAuth2Exception oAuth2Exception = e instanceof OAuth2Exception ? (OAuth2Exception) e : create(null, e.getMessage());
        addErrorCode(oAuth2Exception);
        return oAuth2Exception;
    }

    private void addErrorCode(OAuth2Exception oAuth2Exception) {
        String errorCode = oAuth2Exception.getOAuth2ErrorCode();
        if (INVALID_CLIENT.equals(errorCode)) {
            oAuth2Exception.addAdditionalInformation("error_code", "1001");
        } else if (UNAUTHORIZED_CLIENT.equals(errorCode)) {
            oAuth2Exception.addAdditionalInformation("error_code", "1002");
        } else if (INVALID_GRANT.equals(errorCode)) {
            oAuth2Exception.addAdditionalInformation("error_code", "1003");
        } else if (INVALID_SCOPE.equals(errorCode)) {
            oAuth2Exception.addAdditionalInformation("error_code", "1004");
        } else if (INVALID_TOKEN.equals(errorCode)) {
            oAuth2Exception.addAdditionalInformation("error_code", "1005");
        } else if (INVALID_REQUEST.equals(errorCode)) {
            oAuth2Exception.addAdditionalInformation("error_code", "1006");
        } else if (REDIRECT_URI_MISMATCH.equals(errorCode)) {
            oAuth2Exception.addAdditionalInformation("error_code", "1007");
        } else if (UNSUPPORTED_GRANT_TYPE.equals(errorCode)) {
            oAuth2Exception.addAdditionalInformation("error_code", "1008");
        } else if (UNSUPPORTED_RESPONSE_TYPE.equals(errorCode)) {
            oAuth2Exception.addAdditionalInformation("error_code", "1009");
        } else if (ACCESS_DENIED.equals(errorCode)) {
            oAuth2Exception.addAdditionalInformation("error_code", "1010");
        } else {
            oAuth2Exception.addAdditionalInformation("error_code", "1099");
        }
    }
}
