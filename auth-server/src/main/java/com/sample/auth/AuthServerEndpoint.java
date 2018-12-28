package com.sample.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.KeyPair;
import java.security.Principal;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

@FrameworkEndpoint
@RequiredArgsConstructor
public class AuthServerEndpoint {

    private final KeyPair keyPair;

    @GetMapping("/user")
    @ResponseBody
    public Principal user(Principal user) {
        System.out.println("Inside get USER --------");
        return user;
    }

    @GetMapping("/.well-known/jwks.json")
    @ResponseBody
    public Map<String, Object> getKey() {
        RSAPublicKey publicKey = (RSAPublicKey) this.keyPair.getPublic();
        RSAKey key = new RSAKey.Builder(publicKey).build();
        return new JWKSet(key).toJSONObject();
    }

    @ExceptionHandler(value = Throwable.class)
    public void handle(Throwable t) throws Exception{
        ObjectWriter writer = new ObjectMapper().writerWithDefaultPrettyPrinter();

        System.out.println("-----------------------------");
        System.out.println(writer.writeValueAsString(t));
        System.out.println("-----------------------------");
    }
}
