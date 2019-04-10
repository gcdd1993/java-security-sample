package io.github.gcdd1993.mac;

import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author gaochen
 * @date 2019/4/10
 */
public class MacTest {
    @Test
    public void test() throws NoSuchAlgorithmException, InvalidKeyException {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        SecureRandom secureRandom = new SecureRandom();
        keyGen.init(secureRandom);
        Key key = keyGen.generateKey();
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(key);

        String msg = "gcdd1993";
        byte[] bytes = msg.getBytes();
        byte[] macResult = mac.doFinal(bytes);
        System.out.println(macResult);
    }
}
