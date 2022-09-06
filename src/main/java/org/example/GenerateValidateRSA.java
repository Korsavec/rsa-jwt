package org.example;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class GenerateValidateRSA {

    /*Генерация ключей
    openssl имеется вот тут C:\ Program Files \ Git \ usr \ bin
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
    openssl pkcs8 -topk8 -inform PEM -in private.pem -out private_key.pem -nocrypt*/

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException {

        String jwt = createJwtSignedHMAC();
        System.out.println(jwt);

        Jws<Claims> token = parseJwt(jwt);

        System.out.println(token.getBody());
    }

    public static Jws<Claims> parseJwt(String jwtString) throws InvalidKeySpecException, NoSuchAlgorithmException {

        PublicKey publicKey = getPublicKey();

        Jws<Claims> jwt = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(jwtString);

        return jwt;
    }


    public static String createJwtSignedHMAC() throws InvalidKeySpecException, NoSuchAlgorithmException {

        PrivateKey privateKey = getPrivateKey();

        Instant now = Instant.now();
        String jwtToken = Jwts.builder()
                .claim("name", "Jane Doe")
                .claim("email", "jane@example.com")
                .setSubject("jane")
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(5L, ChronoUnit.MINUTES)))
                .signWith(privateKey)
                .compact();

        return jwtToken;
    }


    private static PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String rsaPublicKey = "-----BEGIN PUBLIC KEY-----" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq5ZPmv1LWdLRp3TuBDch" +
                "IHg3EJjEGksEiJd/a70pE1qLN0dh8RcU0lRNp4t3eEwr348IzZD3HaCdTdSGqZ5v" +
                "P3wLwXeenZuDVRShVSXaIji7jCFG48XX2ZWOkKZls20ZAEQNtCJEa4gLSS/Z48Cs" +
                "V9rtqZ9mBP0Fa8VT6lkKS6+f70wGt2d+IByNrqGbXtcMGzRermMkUobHmR6LdJM3" +
                "/wPhZdEMPtQRYYRY5ZSBFurkuhc1u6u+gN6+SKVwxtA/PZc/jE+I3Wf1FYDZD79b" +
                "i1/bAwBsrxJio5XrJkYACdRvpQ75jX32+U6xG4+W4jmuZ6G8XPxd+JqaZu0OfXSD" +
                "IQIDAQAB" +
                "-----END PUBLIC KEY-----";
        rsaPublicKey = rsaPublicKey.replace("-----BEGIN PUBLIC KEY-----", "");
        rsaPublicKey = rsaPublicKey.replace("-----END PUBLIC KEY-----", "");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(rsaPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(keySpec);
        return publicKey;
    }

    private static PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String rsaPrivateKey = "-----BEGIN PRIVATE KEY-----" +
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrlk+a/UtZ0tGn" +
                "dO4ENyEgeDcQmMQaSwSIl39rvSkTWos3R2HxFxTSVE2ni3d4TCvfjwjNkPcdoJ1N" +
                "1Iapnm8/fAvBd56dm4NVFKFVJdoiOLuMIUbjxdfZlY6QpmWzbRkARA20IkRriAtJ" +
                "L9njwKxX2u2pn2YE/QVrxVPqWQpLr5/vTAa3Z34gHI2uoZte1wwbNF6uYyRShseZ" +
                "Hot0kzf/A+Fl0Qw+1BFhhFjllIEW6uS6FzW7q76A3r5IpXDG0D89lz+MT4jdZ/UV" +
                "gNkPv1uLX9sDAGyvEmKjlesmRgAJ1G+lDvmNffb5TrEbj5biOa5nobxc/F34mppm" +
                "7Q59dIMhAgMBAAECggEAFJWFmzxDq9TkncgjPZI3gSOqx2zsKZNSSeiSuqQIp2+3" +
                "P7xqfXedYdYHMtBCVsYchUctcSuw2XcJJ+sU9IgzJFSHPIBTIOklCjHdYM+XqX9Q" +
                "0HC1hmGXkVylq6iqjqnJ1ARV+IQb3SKG6BK7et0ET83NsQmUPYj0+4bCmFxyJb4L" +
                "hGMRS5QMviE0FGe6OY9I8mv05FQVdg06DPL6ocLsPDTAl+pgKOmreEvp20efg35D" +
                "isPIThHYL5QQB6AjGFV9U//UR4TL2ORC/f82nz2MDiECpfGlOIlU8yOrWQXrgzle" +
                "yOZFVoAzQbq2wMJ7ELWN7/CBk/PLSTxTax0vMeLb2QKBgQDbpQPdx5VIHTmWU0AN" +
                "i64xOMYuKtNQk5fDbMDaSzhEBh2IfX0QrJtcgjzkWzbBS5sOk8odDnoCkqum6Nge" +
                "hxLO2Li8zNYryIq6xeHQJEiuc4H1V8vEk3Gin8La/VflD+ryoAPPJfNH0/AcARmo" +
                "YaZg/p62RHyEq3odpVht2X+llwKBgQDH/PYdY5ETwCMKc2r58+6/m3tNOVrCKHnr" +
                "z7odogscozr7TbGQArH0LFcUcdTmLj3UKZROeSfkZBCWs1mS1gaVZpb/BksU3q2P" +
                "renGvVnIx/2m7IPPC7hGvWfrV7ZoTjfU3MNTquTz+9JbKSNtEDenGgCx8P1udyTk" +
                "+MkbXPhkBwKBgBxiLaa6RONFy4xOg8d8Vm1L7ehHZnlSKVl6s01CTSoVNDnQJZpD" +
                "A+ync+D6nI/MCmSO2p54oXG1rHLsQgln4RlTzkOvoLmVt7+9FJpGJhJNIO0ohE+J" +
                "0jR2usJ73KDgNrdV0EgzmkWc8LldtwgYXlzIapAZN5IZarVsCYpggetPAoGBAKXc" +
                "5PpG48HvrqAyTVz0tORxPXg0w1MYYtXyuLdu96xOrNJUA5oewhxy0d4A8sPdQiY+" +
                "PeQ/k5hWbXOvV/DyVQ9/wGfOfmLWtDff022jCV3+kB7rNf54B+OTnyaO3pfvl1qR" +
                "peY0bCL2jeZRXjJMKvwKEt2Bs470fcLxm0l4eAHtAoGAEDPhIT4ihp3ID2T6Y4oy" +
                "Jp9PAQJMIVSkrtLs9mONLBOb3GBy32+9TM1R5wxyqApwz96R2+kn06IafhY8QjCA" +
                "BRoz1EVvKdIiyiMAgPg/ZDCL5P7OjWBT6Ab+n6KGO/fXgZ/pDsSnrldWM44SCa/j" +
                "FGTCgutv1Cshn/bItoKtF6Q=" +
                "-----END PRIVATE KEY-----";

        rsaPrivateKey = rsaPrivateKey.replace("-----BEGIN PRIVATE KEY-----", "");
        rsaPrivateKey = rsaPrivateKey.replace("-----END PRIVATE KEY-----", "");

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }
}