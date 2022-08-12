package org.example;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class GenerateKeyHMAC512 {

    public static void main(String[] args)  {

        Map<String, Object> claim = new HashMap<>();
        claim.put("firstName","Roman");
        claim.put("lastName","Krasnov");

        String[] roles = {"root", "admin", "user", "supervisor"};

        // withIssuer - Идентификатор (или имя) сервера или системы, выдавшей токен. Обычно DNS-имя, но не обязательно.
        // withIssuedAt - Дата/время выпуска токена.
        // withExpiresAt - Дата/время, когда токен больше не действителен.

        // withAudience - Предполагаемый получатель этого токена; может быть любой строкой, если другой конец использует
        //      ту же строку при проверке токена. Обычно DNS-имя.

        // withSubject - Идентификатор (или имя) пользователя, которого представляет этот токен. А так же может быт любая другая
        //      информация о пользователи.

        // withClaim - Используйте этот раздел, чтобы определить 0 или более пользовательских утверждений для вашего
        //      токена. Тип утверждения может быть любым, равно как и значение.

        // sign - Подпись токена
        String s = JWT.create()
                .withIssuer("SakhShop")
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + (4 * 60 * 60 * 1000)))
                .withAudience("www.sahshop.com")
                .withSubject("test@test.com")

                .withClaim("Authorities", claim)
                .withClaim("auto", "Audi")
                .withArrayClaim("roles", roles)

                .sign(Algorithm.HMAC512("secretKey".getBytes()));

        System.out.println("secretKey");
        System.out.println(s);


        System.out.println(getJWTVerifier().verify(s));

    }

    private static JWTVerifier getJWTVerifier() {

        try {

            Algorithm algorithm = Algorithm.HMAC512("secretKey");

            return JWT.require(algorithm).withIssuer("SakhShop").build();

        } catch (IllegalArgumentException | JWTVerificationException e) {

            throw new RuntimeException("Токен не действителен == " + e);

        }

    }

}
