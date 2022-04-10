
package com.alipay.keymaster;

import static java.sql.DriverManager.println;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.ActionBar;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.UnsupportedEncodingException;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = MainActivity.class.getSimpleName();

    private Button Test;
    private Button Rsa;
    private Button Sm4;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ActionBar actionBar = getSupportActionBar();
        if(actionBar != null){
            actionBar.setHomeButtonEnabled(true);
            actionBar.setDisplayHomeAsUpEnabled(true);
        }

        //keystore测试页面
        Test = (Button) findViewById(R.id.keystore);
        assert Test != null;
        Test.setOnClickListener( new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent it = new Intent(MainActivity.this, KeymasterActivity.class);
                startActivity(it);
            }
        });
        //点击事件，跳转到Key-masterActivity中的onCreate方法


        Rsa = (Button) findViewById(R.id.button_rsa);
        assert Rsa != null;
        Rsa.setOnClickListener ( new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                testAES();
            }
        });//这里点击事件要改一下

        Sm4 = (Button) findViewById(R.id.button_sm4);
        assert Sm4 != null;
        Sm4.setOnClickListener ( new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                testWhiteBoxAES();
            }
        });
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        if(item.getItemId() == android.R.id.home)
        {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void testSM4() throws UnsupportedEncodingException {
        //疑问：iv参数为什么在加解密中一样，还需要分别写两次，如果只写一个结果有什么影响？
        //浅拷贝属于对象克隆的一种，值类型的字段会复制一份，而引用类型的字段拷贝的仅仅是引用地址，而该引用地址指向的实际对象空间其实只有一份；
        //深拷贝相较于上面所示的浅拷贝，除了值类型字段会复制一份，引用类型字段所指向的对象，会在内存中也创建一个副本；
        //这里System.arraycopy(out1, 0, iv, 0, 16)是浅拷贝，如果加密时候把iv给改了，解密的时候iv就是变化了，所以肯定不能只写一个...
        byte[] sourceText = "textdata123456".getBytes("UTF-8");
        byte[] enc_iv = "0123456abcdef120".getBytes("UTF-8");
        byte[] dec_iv = "0123456abcdef120".getBytes("UTF-8");
        SM4Utils sm4Utils = new SM4Utils();
        byte[] keyBytes = SM4Utils.createSM4Key();
        System.out.print("SM4 test：");

        Log.d(TAG, "ECB模式");
        byte[] cipherText = sm4Utils.encryptECB(sourceText, keyBytes);
        Log.d(TAG, "密文：" + Arrays.toString(cipherText));
        byte[] plainText = sm4Utils.decryptECB(cipherText, keyBytes);
        Log.d(TAG, "校验：" + Arrays.equals(sourceText, plainText));

        boolean ecb_result = Arrays.equals(sourceText, plainText);
        TextView ecb_text = findViewById(R.id.txt_sm4_ecb);
        String ecb_showtext = "sm4 ecb test fail";
        if (ecb_result) {
            ecb_showtext = "sm4 ecb test success";
        }
        ecb_text.setText(ecb_showtext.toCharArray(), 0, ecb_showtext.length());


        Log.d(TAG, "CBC模式");
        cipherText = sm4Utils.encryptCBC(sourceText, keyBytes,enc_iv);
        Log.d(TAG, "密文：" + Arrays.toString(cipherText));
        plainText = sm4Utils.decryptCBC(cipherText, keyBytes,dec_iv);
        Log.d(TAG, "校验：" + Arrays.equals(sourceText, plainText));

        boolean cbc_result = Arrays.equals(sourceText, plainText);
        TextView cbc_text = findViewById(R.id.txt_sm4_cbc);
        String cbc_showtext = "sm4 cbc test fail";
        if (cbc_result) {
            cbc_showtext = "sm4 cbc test success";
        }
        cbc_text.setText(cbc_showtext.toCharArray(), 0, cbc_showtext.length());

    }

    public void testRSA() {
        RSA rsa_test = new RSA();
        try {
            // 生成密钥对
            KeyPair keyPair = rsa_test.getKeyPair();
            String privateKey = new String(Base64Utils.encode(keyPair.getPrivate().getEncoded()));
            String publicKey = new String(Base64Utils.encode(keyPair.getPublic().getEncoded()));
            System.out.println("私钥:" + privateKey);
            System.out.println("公钥:" + publicKey);


            // RSA加密
            //String data = "testdata123456"; 加解密测试源数据
            String data = "shjd090701";
            String encryptData = rsa_test.encrypt(data, rsa_test.getPublicKey(publicKey));
            System.out.println("加密后内容:" + encryptData);
            // RSA解密
            String decryptData = rsa_test.decrypt(encryptData, rsa_test.getPrivateKey(privateKey));
            System.out.println("解密后内容:" + decryptData);

            //获取测试结果更新UI
            boolean enc_result = data.equals(decryptData);//这个函数可以做比较，判断加解密是不是成功还原出明文了
            String enc_showtext = "rsa encrypt test fail";
            TextView enc_text = findViewById(R.id.txt_rsa);
            //下四行不需修改，改名字即可
            if (enc_result) {
                enc_showtext = "rsa encrypt test success";
            }
            enc_text.setText(enc_showtext.toCharArray(), 0, enc_showtext.length());


            // RSA签名
            String sign = rsa_test.sign(data, rsa_test.getPrivateKey(privateKey));
            // RSA验签
            boolean sign_result = rsa_test.verify(data, rsa_test.getPublicKey(publicKey), sign);
            System.out.print("验签结果:" + sign_result);

            //获取测试结果更新UI
            String sign_showtext = "rsa sign test fail";
            TextView sign_text = findViewById(R.id.txt_rsa_sign);
            if (sign_result) {
                sign_showtext = "rsa sign test success";
            }
            sign_text.setText(sign_showtext.toCharArray(), 0, sign_showtext.length());
        }

        catch (Exception e) {
            e.printStackTrace();
            System.out.print("加解密异常");
        }
    }



    public void testAES(){
        AES aes_test = new AES();
        try {
            // 生成密钥
            SecretKey key = aes_test.SecretKey();
            // AES加密
            // byte[] plaintext = "textdata123456".getBytes("UTF-8");
            String plaintext = "shjd090701";// 加解密测试源数据
            String encryptData = aes_test.encrypt(plaintext,key);
            System.out.println("加密后内容:" + encryptData);
            // AES解密
            // byte[] encrypt = encryptData.getBytes();
            String decryptData = aes_test.decrypt(encryptData,key);
            System.out.println("解密后内容:" + decryptData);

            //获取测试结果更新UI
            boolean enc_result = plaintext.equals(decryptData);//这个函数可以做比较，判断加解密是不是成功还原出明文了
            String enc_showtext = "AES encrypt test fail";
            TextView enc_text = findViewById(R.id.txt_rsa);
            //下四行不需修改，改名字即可
            if (enc_result) {
                enc_showtext = "AES encrypt test success";
            }
            enc_text.setText(enc_showtext.toCharArray(), 0, enc_showtext.length());

        }
        catch (Exception e) {
            e.printStackTrace();
            System.out.print("加解密异常");
        }


    }



    public void testWhiteBoxAES() {

        String key="aes key";
        mytest mytest = new mytest(key);

        String plain="test aes hahahhahahahah";
        //mytest.setPlaintext(plain);

        mytest.Encrypt(plain);

        byte [] plaintext = mytest.getPlaintext();
        byte [] ciphertext = mytest.getCiphertext();

        byte [] decrypted = mytest.Decrypt();
        mytest.showPlaintext();
        mytest.showCiphertext();

        //获取测试结果更新UI
        boolean ecb_result = Arrays.equals(plaintext, decrypted);
        TextView ecb_text = findViewById(R.id.txt_sm4_ecb);
        String ecb_showtext = "aes test fail";
        if (ecb_result) {
            ecb_showtext = "aes test success";
        }
        ecb_text.setText(ecb_showtext.toCharArray(), 0, ecb_showtext.length());


    }


    public void mytest_aes(){
            //char plain[] = {"test aes hahahhahahahah"};
            char mw[] = {0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31,              //明文
                    0x37,0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34};
            char backup[] = {0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31,              //copy
                    0x37,0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34};
            char key[] = {0x2b, 0x28, 0xab, 0x09, 0x7e, 0xae, 0xf7,             //密钥
                    0xcf,0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c};
            //char mw[] = {"1234567893216549"};
            //char key[] = {"1234567891234561"};
            mytest_aes mytest_aes = new mytest_aes(key);

            System.out.print("明文：");
            for(int i = 0; i < 16; i++){
                System.out.print(mw[i]);
                // println ("%0X ",mw[i]);
            }

            System.out.print("密钥：");
            for(int i = 0; i < 16; i++){
                System.out.print(key[i]);
            }
            mytest_aes.Cipher(mw);
            System.out.print("加密后：");
            //printf("%s",mw);
            for(int i = 0; i < 16; i++){
                System.out.print(mw[i]);
            }

            mytest_aes.InvCipher(mw);
            System.out.print("解密后：");
            for(int i = 0; i < 16; i++){
                System.out.print(mw[i]);
            }

        //获取测试结果更新UI
        boolean ecb_result = Arrays.equals(backup, mw);
        TextView ecb_text = findViewById(R.id.txt_sm4_ecb);
        String ecb_showtext = "aes test fail";
        if (ecb_result) {
            ecb_showtext = "aes test success";
        }
        ecb_text.setText(ecb_showtext.toCharArray(), 0, ecb_showtext.length());

    }


}



