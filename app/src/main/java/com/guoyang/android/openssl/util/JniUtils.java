package com.guoyang.android.openssl.util;

/**
 * Created by guoyang on 2018/1/17.
 * github https://github.com/GuoYangGit
 * QQ:352391291
 */

public class JniUtils {
    static {
        System.loadLibrary("crypto");
        System.loadLibrary("cipher");
    }

    /**
     * HmacSHA1签名
     *
     * @param src
     * @return
     */
    public native byte[] encodeByHmacSHA1(byte[] src);

    /**
     * SHA1签名
     *
     * @param src
     * @return
     */
    public native String encodeBySHA1(byte[] src);

    /**
     * SHA512签名
     *
     * @param src
     * @return
     */
    public native String encodeBySHA512(byte[] src);

    /**
     * MD5
     *
     * @param src
     * @return
     */
    public native String MD5(byte[] src);

    public native String getAESKeY(int length);

    /**
     * AES加密
     *
     * @param keys
     * @param src
     * @return
     */
    public native byte[] encodeByAES(byte[] keys, byte[] src);

    /**
     * AES解密
     *
     * @param keys
     * @param src
     * @return
     */
    public native byte[] decodeByAES(byte[] keys, byte[] src);

    /**
     * RSA公钥加密
     *
     * @param keys
     * @param src
     * @return
     */
    public native byte[] encodeByRSAPubKey(byte[] keys, byte[] src);

    /**
     * RSA公钥解密
     *
     * @param keys
     * @param src
     * @return
     */
    public native byte[] decodeByRSAPubKey(byte[] keys, byte[] src);

    /**
     * RSA私钥加密
     *
     * @param keys
     * @param src
     * @return
     */
    public native byte[] encodeByRSAPrivateKey(byte[] keys, byte[] src);

    /**
     * RSA私钥解密
     *
     * @param keys
     * @param src
     * @return
     */
    public native byte[] decodeByRSAPrivateKey(byte[] keys, byte[] src);

}
