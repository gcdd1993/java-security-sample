package io.github.gcdd1993.crypto;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * @author gaochen
 * @date 2019/4/10
 */
public class CryptoTest {
    @Test
    public void test() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String data = "gcdd1993";
        Random random = new Random();
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        random.nextBytes(key);
        random.nextBytes(iv);
        byte[] encrypted1 = data.getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] original = cipher.doFinal(encrypted1);

        // 解密
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] bytes = cipher.doFinal(original);
        Assert.assertEquals(data, new String(bytes, StandardCharsets.UTF_8));
    }
}
