package com.sp.fc.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

public class JWTSimpleTest {

    private void printToken(String token){
        String[] tokens = token.split("\\.");
        System.out.println("header >>> " + new String(Base64.getDecoder().decode(tokens[0])));
        System.out.println("body >>> " + new String(Base64.getDecoder().decode(tokens[1])));
    }

    @DisplayName("1. jjwt 를 이용한 토큰 테스트")
    @Test
    void test_1(){
        String okta_token = Jwts.builder()
                .addClaims(
                        Map.of("name", "shbae", "price", 3000)
                ).signWith(SignatureAlgorithm.HS256, "shbae")
                .compact();
        printToken(okta_token);

        Jws<Claims> tokenInfo = Jwts.parser().setSigningKey("shbae").parseClaimsJws(okta_token);
        System.out.println(tokenInfo);
    }


    @DisplayName("2. java-jwt 를 이용한 토큰 테스트")
    @Test
    void test_2() {

        byte[] SEC_KEKY = DatatypeConverter.parseBase64Binary("shbae");

        String oauth0_token = JWT.create()
                .withClaim("name", "shbae")
                .withClaim("price", 7000)
                .sign(Algorithm.HMAC256("shbae"));
        printToken(oauth0_token);

        DecodedJWT verified = JWT.require(Algorithm.HMAC256("shbae")).build().verify(oauth0_token);
        System.out.println(verified.getClaims());


    }

    @DisplayName("3. 만료 시간 테스트")
    @Test
    void test_3() throws InterruptedException {
        final Algorithm AL = Algorithm.HMAC256("shbae");

        String token = JWT.create()
                .withSubject("a1234")
                .withNotBefore(new Date(System.currentTimeMillis()+1000)) // 1초 지나기 전에는 검증 X
                .withExpiresAt(new Date(System.currentTimeMillis()+3000))
                .sign(AL);

//        Thread.sleep(2000); // 만료시간 1초 설정후 2초 쉬게하면 만료된 토큰으로 오류
        try{
            DecodedJWT verify = JWT.require(AL).build().verify(token);
            System.out.println(verify.getClaims());
        }catch (Exception e){
            System.out.println("유효하지 않은 토큰입니다...");
            DecodedJWT decode = JWT.decode(token);
            System.out.println(decode.getClaims());
        }


    }


}
