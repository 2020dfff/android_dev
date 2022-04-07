package com.alipay.keymaster;

// 密钥白盒化是指能够在白盒环境下抵御攻击的一种特殊的加密方法。其核心思想是混淆，意思是让密钥以一种完全无法理解的形式存在，但不影响密钥本身发挥作用。
// 密钥白盒化将算法和密钥进行深度融合，由算法和密钥生成一个加密表和解密表，应用运行时通过查找加解密表来进行加解密，不在依赖于原来的加解密算法和密码。
// 通过算法和密钥的高度融合，可以有效的隐藏密钥，同时在运行时内存中不会出现密钥，从而防止密钥被静态分析和动态调试。

public class mytest {
    private byte[] key=null;
    private char[] ikey=null;
    private byte[] plaintext=null;
    private byte[] ciphertext= null;
    private static char Rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    private static char[] S= {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };
    private static char[] InvS= {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
    private static char x2time (char in)
    {
        char temp;
        temp = (char) (in<<1);
        if((in & 0x80)==0x80)
            temp ^= 0x1b;
        return (char) (temp&0xff);
    }
    private static char x3time(char in) {
        return (char) (x2time(in)^in);
    }
    private static char x9time(char in) {
        return (char) (x2time(x2time((char) x2time(in)))^in);
    }
    private static char xbtime(char in) {
        return (char) (x2time(x2time(x2time(in)))^x2time(in)^in);
    }
    private static char xdtime(char in) {
        return (char) (x2time(x2time(x2time(in)))^x2time(x2time(in))^in);
    }
    private static char xetime(char in) {
        return (char) (x2time(x2time(x2time(in)))^x2time(x2time(in))^x2time(in));
    }

    public mytest(String key) {
        setKey(key);
        setPlaintext(new byte[0]);
        setCiphertext(new byte[0]);
    }
    public mytest(byte[] key) {
        setKey(key);
        setPlaintext(new byte[0]);
        setCiphertext(new byte[0]);
    }
    public mytest() {
        setKey(new byte[0]);
        setPlaintext(new byte[0]);
        setCiphertext(new byte[0]);
    }

    private void geneKey() {
        int i,j;
        this.ikey=new char[11*16];
        char[] T=new char[4];
        for(i=0;i<16;i++)
            this.ikey[i]=(char)(this.key[i]&0xff);
        for(i=4;i<44;i++) {
            if(i%4==0) {
                T[0]=(char) (S[this.ikey[4*i-3]]^Rcon[i/4-1]);
                T[1]=(char) (S[this.ikey[4*i-2]]);
                T[2]=(char) (S[this.ikey[4*i-1]]);
                T[3]=(char) (S[this.ikey[4*i-4]]);
                for(j=4*i;j<4*i+4;j++)
                    this.ikey[j]=(char) (this.ikey[j-16]^T[j%4]&0xff);
            }else {
                for(j=4*i;j<4*i+4;j++)
                    this.ikey[j]=(char) (this.ikey[j-16]^this.ikey[j-4]&0xff);
            }
        }
    }

    private byte[] EncryptRound(byte[] bin,int start) {
        byte[] out=new byte[16];
        char[] in=byteTochar(bin);
        out[0]=(byte) (x2time(S[in[0]])^x3time(S[in[5]])^S[in[10]]^S[in[15]]^this.ikey[start]);
        out[1]=(byte) (x2time(S[in[1]])^x3time(S[in[6]])^S[in[11]]^S[in[12]]^this.ikey[start+1]);
        out[2]=(byte) (x2time(S[in[2]])^x3time(S[in[7]])^S[in[8]]^S[in[13]]^this.ikey[start+2]);
        out[3]=(byte) (x2time(S[in[3]])^x3time(S[in[4]])^S[in[9]]^S[in[14]]^this.ikey[start+3]);

        out[4]=(byte) (S[in[0]]^x2time(S[in[5]])^x3time(S[in[10]])^S[in[15]]^this.ikey[start+4]);
        out[5]=(byte) (S[in[1]]^x2time(S[in[6]])^x3time(S[in[11]])^S[in[12]]^this.ikey[start+5]);
        out[6]=(byte) (S[in[2]]^x2time(S[in[7]])^x3time(S[in[8]])^S[in[13]]^this.ikey[start+6]);
        out[7]=(byte) (S[in[3]]^x2time(S[in[4]])^x3time(S[in[9]])^S[in[14]]^this.ikey[start+7]);

        out[8]=(byte) (S[in[0]]^S[in[5]]^x2time(S[in[10]])^x3time(S[in[15]])^this.ikey[start+8]);
        out[9]=(byte) (S[in[1]]^S[in[6]]^x2time(S[in[11]])^x3time(S[in[12]])^this.ikey[start+9]);
        out[10]=(byte) (S[in[2]]^S[in[7]]^x2time(S[in[8]])^x3time(S[in[13]])^this.ikey[start+10]);
        out[11]=(byte) (S[in[3]]^S[in[4]]^x2time(S[in[9]])^x3time(S[in[14]])^this.ikey[start+11]);

        out[12]=(byte) (x3time(S[in[0]])^S[in[5]]^S[in[10]]^x2time(S[in[15]])^this.ikey[start+12]);
        out[13]=(byte) (x3time(S[in[1]])^S[in[6]]^S[in[11]]^x2time(S[in[12]])^this.ikey[start+13]);
        out[14]=(byte) (x3time(S[in[2]])^S[in[7]]^S[in[8]]^x2time(S[in[13]])^this.ikey[start+14]);
        out[15]=(byte) (x3time(S[in[3]])^S[in[4]]^S[in[9]]^x2time(S[in[14]])^this.ikey[start+15]);
        return out;
    }

    private byte[] EncryptLastRound(byte[] bin) {
        char[] in=byteTochar(bin);
        byte[] out=new byte[16];
        out[0]=(byte) (S[in[0]]^this.ikey[160]);
        out[1]=(byte) (S[in[1]]^this.ikey[161]);
        out[2]=(byte) (S[in[2]]^this.ikey[162]);
        out[3]=(byte) (S[in[3]]^this.ikey[163]);

        out[4]=(byte) (S[in[5]]^this.ikey[164]);
        out[5]=(byte) (S[in[6]]^this.ikey[165]);
        out[6]=(byte) (S[in[7]]^this.ikey[166]);
        out[7]=(byte) (S[in[4]]^this.ikey[167]);

        out[8]=(byte) (S[in[10]]^this.ikey[168]);
        out[9]=(byte) (S[in[11]]^this.ikey[169]);
        out[10]=(byte) (S[in[8]]^this.ikey[170]);
        out[11]=(byte) (S[in[9]]^this.ikey[171]);

        out[12]=(byte) (S[in[15]]^this.ikey[172]);
        out[13]=(byte) (S[in[12]]^this.ikey[173]);
        out[14]=(byte) (S[in[13]]^this.ikey[174]);
        out[15]=(byte) (S[in[14]]^this.ikey[175]);
        return out;
    }

    private byte[] DecryptRound(byte[] in,int start) {

        char[] lineTran=byteTochar(DecryptLastRound(in,start));
        byte[] output=new byte[16];
        output[0]=(byte) (xetime(lineTran[0])^xbtime(lineTran[4])^xdtime(lineTran[8])^x9time(lineTran[12]));
        output[1]=(byte) (xetime(lineTran[1])^xbtime(lineTran[5])^xdtime(lineTran[9])^x9time(lineTran[13]));
        output[2]=(byte) (xetime(lineTran[2])^xbtime(lineTran[6])^xdtime(lineTran[10])^x9time(lineTran[14]));
        output[3]=(byte) (xetime(lineTran[3])^xbtime(lineTran[7])^xdtime(lineTran[11])^x9time(lineTran[15]));

        output[4]=(byte) (x9time(lineTran[0])^xetime(lineTran[4])^xbtime(lineTran[8])^xdtime(lineTran[12]));
        output[5]=(byte) (x9time(lineTran[1])^xetime(lineTran[5])^xbtime(lineTran[9])^xdtime(lineTran[13]));
        output[6]=(byte) (x9time(lineTran[2])^xetime(lineTran[6])^xbtime(lineTran[10])^xdtime(lineTran[14]));
        output[7]=(byte) (x9time(lineTran[3])^xetime(lineTran[7])^xbtime(lineTran[11])^xdtime(lineTran[15]));

        output[8]=(byte) (xdtime(lineTran[0])^x9time(lineTran[4])^xetime(lineTran[8])^xbtime(lineTran[12]));
        output[9]=(byte) (xdtime(lineTran[1])^x9time(lineTran[5])^xetime(lineTran[9])^xbtime(lineTran[13]));
        output[10]=(byte) (xdtime(lineTran[2])^x9time(lineTran[6])^xetime(lineTran[10])^xbtime(lineTran[14]));
        output[11]=(byte) (xdtime(lineTran[3])^x9time(lineTran[7])^xetime(lineTran[11])^xbtime(lineTran[15]));

        output[12]=(byte) (xbtime(lineTran[0])^xdtime(lineTran[4])^x9time(lineTran[8])^xetime(lineTran[12]));
        output[13]=(byte) (xbtime(lineTran[1])^xdtime(lineTran[5])^x9time(lineTran[9])^xetime(lineTran[13]));
        output[14]=(byte) (xbtime(lineTran[2])^xdtime(lineTran[6])^x9time(lineTran[10])^xetime(lineTran[14]));
        output[15]=(byte) (xbtime(lineTran[3])^xdtime(lineTran[7])^x9time(lineTran[11])^xetime(lineTran[15]));

        return output;
    }
    private byte[] DecryptLastRound(byte[] bin,int start) {
        char[] in=byteTochar(bin);
        byte[] lineTran=new byte[16];
        lineTran[0]=(byte) (InvS[in[0]]^this.ikey[start]);
        lineTran[1]=(byte) (InvS[in[1]]^this.ikey[start+1]);
        lineTran[2]=(byte) (InvS[in[2]]^this.ikey[start+2]);
        lineTran[3]=(byte) (InvS[in[3]]^this.ikey[start+3]);

        lineTran[4]=(byte) (InvS[in[7]]^this.ikey[start+4]);
        lineTran[5]=(byte) (InvS[in[4]]^this.ikey[start+5]);
        lineTran[6]=(byte) (InvS[in[5]]^this.ikey[start+6]);
        lineTran[7]=(byte) (InvS[in[6]]^this.ikey[start+7]);

        lineTran[8]=(byte) (InvS[in[10]]^this.ikey[start+8]);
        lineTran[9]=(byte) (InvS[in[11]]^this.ikey[start+9]);
        lineTran[10]=(byte) (InvS[in[8]]^this.ikey[start+10]);
        lineTran[11]=(byte) (InvS[in[9]]^this.ikey[start+11]);

        lineTran[12]=(byte) (InvS[in[13]]^this.ikey[start+12]);
        lineTran[13]=(byte) (InvS[in[14]]^this.ikey[start+13]);
        lineTran[14]=(byte) (InvS[in[15]]^this.ikey[start+14]);
        lineTran[15]=(byte) (InvS[in[12]]^this.ikey[start+15]);

        return lineTran;
    }
    public void Encrypt() {
        byte[] inout=new byte[16];
        for(int i=0;i<16;i++)
            inout[i]=(byte) (this.plaintext[i]^this.ikey[i]);
        for(int j=0;j<9;j++)
            inout=EncryptRound(inout,16*j+16);
        this.ciphertext=EncryptLastRound(inout);
    }
    public byte [] Decrypt() {
        byte[] inout=new byte[16];
        for(int i=0;i<16;i++)
            inout[i]=(byte) (this.ciphertext[i]^this.ikey[i+160]);
        for(int j=0;j<9;j++)
            inout=DecryptRound(inout,(9-j)*16);
        this.plaintext=DecryptLastRound(inout,0);
        byte [] decrypted = this.plaintext;
        return decrypted;
    }

    public void Encrypt(String plaintext) {
        setPlaintext(plaintext);
        Encrypt();
    }
    public void Encrypt(byte[] plaintext) {
        setPlaintext(plaintext);
        Encrypt();
    }
    public void Decrypt(String ciphertext) {
        setCiphertext(ciphertext);
        Decrypt();
    }
    public void Decrypt(byte[] ciphertext) {
        setCiphertext(ciphertext);
        Decrypt();
    }
    public void showIkey() {
        int i,j;
        for(i=0;i<44;i++) {
            if(i%4==0)System.out.print(String.format("k%d:    ",i/4));
            for(j=4*i;j<4*i+4;j++)
                System.out.print(String.format("%02x ",this.ikey[j]));
            if(i%4==3)System.out.println();
        }
    }
    public void showInfo() {
        showKey();
        showIkey();
        showPlaintext();
        showCiphertext();
    }
    public void showKey() {
        int i;
        System.out.print("Key:\n  Hex:");
        for(i=0;i<16;i++)
            System.out.print(String.format("%02x ",this.key[i]));
        System.out.print("\n  CH:");
        String strKey=new String(this.key);
        System.out.println(strKey);
    }
    public void showPlaintext() {
        int i;
        System.out.print("Plaintext:\n  Hex:");
        for(i=0;i<16;i++)
            System.out.print(String.format("%02x ",this.plaintext[i]));
        System.out.print("\n  CH:");
        String strPlaintext=new String(this.plaintext);
        System.out.println(strPlaintext);
    }
    public void showCiphertext() {
        int i;
        System.out.print("Ciphertext:\n  Hex:");
        for(i=0;i<16;i++)
            System.out.print(String.format("%02x ",this.ciphertext[i]));
        System.out.println();
    }
    public void setKey(byte[] key) {
        this.key=new byte[16];
        int n=key.length>16?16:key.length;
        for(int i=0;i<n;i++)
            this.key[i] = key[i];
        geneKey();
    }
    public void setKey(String key) {
        setKey(key.getBytes());
    }
    public byte[] getPlaintext() {
        return this.plaintext;
    }
    public void setPlaintext(byte[] plaintext) {
        this.plaintext=new byte[16];
        int n=plaintext.length>16?16:plaintext.length;
        for(int i=0;i<n;i++)
            this.plaintext[i] = plaintext[i];
    }
    public void setPlaintext(String plaintext) {
        setPlaintext(plaintext.getBytes());
    }
    public byte[] getCiphertext() {
        return this.ciphertext;
    }
    public void setCiphertext(byte[] ciphertext) {
        this.ciphertext=new byte[16];
        int n=ciphertext.length>16?16:ciphertext.length;
        for(int i=0;i<n;i++)
            this.ciphertext[i] = ciphertext[i];
    }
    public void setCiphertext(String ciphertext) {
        setCiphertext(ciphertext.getBytes());
    }
    public char[] byteTochar(byte[] byteArray) {
        char[] charArray=new char[byteArray.length];
        for(int i=0;i<byteArray.length;i++)
            charArray[i]=(char) (byteArray[i]&0xff);
        return charArray;
    }
}
