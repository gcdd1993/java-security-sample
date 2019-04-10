package io.github.gcdd1993.signature.SignatureTest;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * @author gaochen
 * @date 2019/4/10
 */
public class SignatureTest {
    @Test
    public void test() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //Creating KeyPair generator object
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
        //Initializing the KeyPairGenerator
        keyPairGen.initialize(2048);
        //Generate the pair of keys
        KeyPair pair = keyPairGen.generateKeyPair();
        //Getting the private key from the key pair
        PrivateKey privateKey = pair.getPrivate();
        //Creating a Signature object
        Signature sign = Signature.getInstance("SHA256withDSA");
        //Initialize the signature
        sign.initSign(privateKey);

        String msg = "gcdd1993";
        sign.update(msg.getBytes());
        byte[] signature = sign.sign();

        sign.initVerify(pair.getPublic());
        sign.update(msg.getBytes());
        boolean verify = sign.verify(signature);
        Assert.assertTrue(verify);

    }

    @Test
    public void testCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //Creating KeyPair generator object
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        //Initializing the KeyPairGenerator
        keyPairGen.initialize(2048);
        //Generate the pair of keys
        KeyPair pair = keyPairGen.generateKeyPair();
        //Getting the private key from the key pair
        PublicKey publicKey = pair.getPublic();

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        String msg = "gcdd1993";
        cipher.update(msg.getBytes());
        byte[] cipherText = cipher.doFinal();

        cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
        byte[] decipheredText = cipher.doFinal(cipherText);

        Assert.assertEquals(msg, new String(decipheredText));
    }
}
