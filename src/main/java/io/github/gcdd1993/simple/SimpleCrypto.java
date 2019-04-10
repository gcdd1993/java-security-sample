package io.github.gcdd1993.simple;

import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author gaochen
 * @date 2019/4/10
 */
public class SimpleCrypto {
    @Test
    public void md5Test() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-224");
        md.update("gcdd1993".getBytes());
        byte[] digest = md.digest();
        StringBuffer hexString = new StringBuffer();

        for (byte aDigest : digest) {
            hexString.append(Integer.toHexString(0xFF & aDigest));
        }
        System.out.println("Hex format : " + hexString.toString());
    }
}
