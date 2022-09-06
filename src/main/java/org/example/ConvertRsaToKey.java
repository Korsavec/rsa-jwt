package org.example;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ConvertRsaToKey {

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, URISyntaxException {

        String privateKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("private_key.pem").toURI())));
        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));


        String publicKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("public.pem").toURI())));
        publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));



        KeyFactory kf = KeyFactory.getInstance("RSA");

        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

        System.out.println(privKey);
        System.out.println(pubKey);
    }

}
