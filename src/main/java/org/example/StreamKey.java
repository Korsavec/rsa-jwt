package org.example;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class StreamKey {

    public static void main(String[] args) {

        StreamKey key = new StreamKey();
        key.getSer();

    }

    private void getSer() {

        try  {

            InputStream inputStream = getClass().getClassLoader().getResourceAsStream("keystore");

            char[] password = "111111".toCharArray();
            String alias = "client";

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(inputStream, password);

            Key key = keyStore.getKey(alias, password);

            LocalDateTime currentTime = LocalDateTime.now();
            Date dat = Date.from(currentTime.plusMinutes(5).atZone(ZoneId.systemDefault()).toInstant());

            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", alias);
            claims.put("exp", dat.getTime());

            String token = Jwts.builder()
                    .setHeaderParam("alg", "RS256")
                    .setHeaderParam("typ", "jwt")
                    .setClaims(claims)
                    .signWith(key, SignatureAlgorithm.RS256).compact();

            System.out.println(token);

        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException |
                 UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }


    }


}
