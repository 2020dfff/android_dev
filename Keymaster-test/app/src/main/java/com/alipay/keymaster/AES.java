package com.alipay.keymaster;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyGenerator;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;


public class AES {

    /**
     * 获取密钥对
     *
     * @return 密钥对
     */
    public static SecretKey SecretKey() throws Exception {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        return key;
    }

    /**
     * AES加密
     *
     * @param data 待加密数据
     * @return
     */

    public static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        //data
        byte[] cipher_text = data.getBytes();
        byte[] ciphertext = cipher.doFinal(cipher_text);
        return new String(Base64Utils.encode(ciphertext));
    }

    /**
     * AES解密
     * @param data 待解密数据
     * @return
     */
    public static String decrypt(String data, SecretKey key) throws Exception {
        // byte[] encrypted = Base64Utils.decode(data);
        Cipher cipher = Cipher.getInstance("");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plain_text = data.getBytes();
        byte[] plaintext = cipher.doFinal(plain_text);
        return new String(Base64Utils.encode(plaintext));
    }

}