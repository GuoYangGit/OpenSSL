#include <jni.h>
#include <string>
#include <Android/log.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <string.h>

#define TAG "JNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

extern "C" {
//HmacSHA1签名
JNIEXPORT jbyteArray JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_encodeByHmacSHA1(JNIEnv *env, jobject instance,
                                                                jbyteArray value_) {
    const char *key = "5fd6s4gs8f7s1dfv23sdf4ag65rg4arhb4fb1f54bgf5gbvf1534as";
    LOGI("HmacSHA1->准备获取待加密数据");
    jbyte *value = env->GetByteArrayElements(value_, NULL);
    LOGI("HmacSHA1->准备计算待加密数据长度");
    jsize value_Len = env->GetArrayLength(value_);

    unsigned int result_len;
    unsigned char result[EVP_MAX_MD_SIZE];
    char buff[EVP_MAX_MD_SIZE];
    char hex[EVP_MAX_MD_SIZE];

    LOGI("HmacSHA1->准备进行加密计算");
    HMAC(EVP_sha1(), key, strlen(key), (unsigned char *) value, value_Len, result, &result_len);
    LOGI("HmacSHA1->加密计算结束");

    strcpy(hex, "");
    for (int i = 0; i != result_len; ++i) {
        sprintf(buff, "%02x", result[i]);
        strcat(hex, buff);
    }
    LOGI("HmacSHA1->%s", hex);
    env->ReleaseByteArrayElements(value_, value, 0);
    LOGI("HmacSHA1->jni释放数据结束");
    jbyteArray signature = env->NewByteArray(strlen(hex));
    env->SetByteArrayRegion(signature, 0, strlen(hex), (jbyte *) hex);
    LOGI("HmacSHA1->准备以ByteArray格式返回数据");
    return signature;
}

/**
 * SHA加密
 * 特点：
 * 1.输出长度固定。
 * 2.不可逆。
 * 3.对输入数据敏感(数据变化小时，输出数据也会发生明显变化)。
 * 4.防碰撞(不同数据得到相同对输出数据对可能性低)
 */
JNIEXPORT jstring JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_encodeBySHA1(JNIEnv *env, jobject instance,
                                                            jbyteArray value_) {
    jbyte *value = env->GetByteArrayElements(value_, NULL);
    jsize value_len = env->GetArrayLength(value_);

    char buff[SHA_DIGEST_LENGTH];
    char hex[SHA_DIGEST_LENGTH * 2];
    unsigned char digest[SHA_DIGEST_LENGTH];

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    LOGI("SHA1->正在进行SHA1哈希计算");
    SHA1_Update(&ctx, value_, value_len);
    SHA1_Final(digest, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));
    strcpy(hex, "");
    LOGI("SHA1->把哈希值按%%02x格式定向到缓冲区");
    for (int i = 0; i != sizeof(digest); ++i) {
        sprintf(buff, "%02x", digest[i]);
        strcat(hex, buff);
    }
    LOGI("SHA1->%s", hex);

    LOGI("SHA1->从jni释放数据指针");
    env->ReleaseByteArrayElements(value_, value, 0);
    return env->NewStringUTF(hex);
}

/**
 * SHA512加密
 * 特点：
 * 1.输出长度固定。
 * 2.不可逆。
 * 3.对输入数据敏感(数据变化小时，输出数据也会发生明显变化)。
 * 4.防碰撞(不同数据得到相同对输出数据对可能性低)
 */
JNIEXPORT jstring JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_encodeBySHA512(JNIEnv *env, jobject instance,
                                                              jbyteArray value_) {
    jbyte *value = env->GetByteArrayElements(value_, NULL);
    jsize value_len = env->GetArrayLength(value_);

    char buff[SHA512_DIGEST_LENGTH];
    char hex[SHA512_DIGEST_LENGTH * 2];
    unsigned char digest[SHA512_DIGEST_LENGTH];

    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    LOGI("SHA512->正在进行SHA256哈希计算");
    SHA512_Update(&ctx, value, value_len);
    SHA512_Final(digest, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));
    strcpy(hex, "");
    LOGI("SHA512->把哈希值按%%02x格式定向到缓冲区");
    for (int i = 0; i != sizeof(digest); ++i) {
        sprintf(buff, "%02x", digest[i]);
        strcat(hex, buff);
    }
    LOGI("SHA512->%s", hex);

    LOGI("SHA512->从jni释放数据指针");
    env->ReleaseByteArrayElements(value_, value, 0);

    return env->NewStringUTF(hex);
}

JNIEXPORT jstring JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_MD5(JNIEnv *env, jobject instance,
                                                   jbyteArray value_) {
    LOGI("MD5->信息摘要算法");
    jbyte *value = env->GetByteArrayElements(value_, NULL);
    jsize value_len = env->GetArrayLength(value_);

    char buff[3] = {"\0"};
    char hex[33] = {"\0"};
    unsigned char digest[MD5_DIGEST_LENGTH];

    MD5_CTX ctx;
    MD5_Init(&ctx);
    LOGI("MD5->进行MD5信息摘要运算");
    MD5_Update(&ctx, value, value_len);
    MD5_Final(digest, &ctx);

    strcpy(hex, "");
    LOGI("MD5->把哈希值按%%02x格式定向到缓冲区");
    for (int i = 0; i != sizeof(digest); ++i) {
        sprintf(buff, "%02x", digest[i]);
        strcat(hex, buff);
    }
    LOGI("MD5->%s", hex);

    LOGI("MD5->从jni释放数据指针");
    env->ReleaseByteArrayElements(value_, value, 0);
    return env->NewStringUTF(hex);
}

JNIEXPORT jstring JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_getAESKeY(JNIEnv *env, jobject instance,
                                                         jint value_) {
    char pool[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                   'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                   'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                   'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
                   'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                   'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                   'Y', 'Z'};
    srand(time(0));
    char aes_key[value_ + 1];
    aes_key[value_] = '\0';
    int i = 0;
    while (i != value_) {
        aes_key[i++] = pool[rand() % sizeof(pool)];
    }
    LOGI("AESKey->%s", aes_key);
    return env->NewStringUTF(aes_key);
}

JNIEXPORT jbyteArray JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_encodeByAES(JNIEnv *env, jobject instance,
                                                           jbyteArray keys_,
                                                           jbyteArray value_) {
    LOGI("AES->对称密钥，也就是说加密和解密用的是同一个密钥");
    const unsigned char *iv = (const unsigned char *) "0102030405060708";
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *value = env->GetByteArrayElements(value_, NULL);
    jsize value_len = env->GetArrayLength(value_);

    int outlen = 0, cipherText_len = 0;
    unsigned char *out = (unsigned char *) malloc((value_len / 16 + 1) * 16);
    //清除内存空间
    memset(out, 0, (value_len / 16 + 1) * 16);
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    LOGI("AES->指定加密算法，初始化加密key/iv");
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) keys, iv);
    LOGI("AES->对数据进行加密运算");
    EVP_EncryptUpdate(&ctx, out, &outlen, (const unsigned char *) value, value_len);
    cipherText_len = outlen;
    LOGI("AES->结束加密运算");
    EVP_EncryptFinal_ex(&ctx, out + outlen, &outlen);
    cipherText_len += outlen;
    LOGI("AES->EVP_CIPHER_CTX_cleanup");
    EVP_CIPHER_CTX_cleanup(&ctx);
    LOGI("AES->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(value_, value, 0);
    jbyteArray cipher = env->NewByteArray(cipherText_len);
    LOGI("AES->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, cipherText_len, (jbyte *) out);
    LOGI("AES->释放内存");
    free(out);
    return cipher;
}

JNIEXPORT jbyteArray JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_decodeByAES(JNIEnv *env, jobject instance,
                                                           jbyteArray keys_,
                                                           jbyteArray value_) {
    LOGI("AES->对称密钥，也就是说加密和解密用的是同一个密钥");
    const unsigned char *iv = (const unsigned char *) "0102030405060708";
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *value = env->GetByteArrayElements(value_, NULL);
    jsize value_len = env->GetArrayLength(value_);

    int outlen = 0, plaintext_len = 0;
    unsigned char *out = (unsigned char *) malloc(value_len);
    memset(out, 0, value_len);
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    LOGI("AES->指定解密算法，初始化解密key/iv");
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) keys, iv);
    LOGI("AES->对数据进行解密运算");
    EVP_DecryptUpdate(&ctx, out, &outlen, (const unsigned char *) value, value_len);
    plaintext_len = outlen;
    LOGI("AES->结束解密运算");
    EVP_DecryptFinal_ex(&ctx, out + outlen, &outlen);
    plaintext_len += outlen;

    LOGI("AES->EVP_CIPHER_CTX_cleanup");
    EVP_CIPHER_CTX_cleanup(&ctx);

    LOGI("AES->从jni释放数据指针");
    env->ReleaseByteArrayElements(value_, value, 0);
    env->ReleaseByteArrayElements(keys_, keys, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_len);
    LOGI("AES->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, plaintext_len, (jbyte *) out);
    LOGI("AES->释放内存");
    free(out);

    return cipher;
}

JNIEXPORT jbyteArray JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_encodeByRSAPubKey(JNIEnv *env, jobject instance,
                                                                 jbyteArray keys_,
                                                                 jbyteArray value_) {
    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *value = env->GetByteArrayElements(value_, NULL);
    jsize value_len = env->GetArrayLength(value_);

    int ret = 0, value_flen = 0, cipherText_offset = 0, desText_len = 0, value_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    LOGI("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(keys, -1);
    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    desText_len = flen * (value_len / (flen - 11) + 1);

    unsigned char *valueOrigin = (unsigned char *) malloc(value_len);
    unsigned char *cipherText = (unsigned char *) malloc(flen);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    memset(valueOrigin, 0, value_len);
    memcpy(valueOrigin, value, value_len);

    LOGI("RSA->对数据进行公钥加密运算");
    //RSA_PKCS1_PADDING最大加密长度：128-11；RSA_NO_PADDING最大加密长度：128
    for (int i = 0; i <= value_len / (flen - 11); ++i) {
        value_flen = (i == value_len / (flen - 11) ? value_len % (flen - 11) : flen - 11);
        if (value_flen == 0) {
            break;
        }

        memset(cipherText, 0, flen);
        ret = RSA_public_encrypt(value_flen, valueOrigin + value_offset, cipherText, rsa,
                                 RSA_PKCS1_PADDING);

        memcpy(desText + cipherText_offset, cipherText, ret);
        cipherText_offset += ret;
        value_offset += value_flen;
    }

    RSA_free(rsa);
    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(value_, value, 0);
    env->ReleaseByteArrayElements(keys_, keys, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_offset);
    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (const jbyte *) desText);
    LOGI("RSA->释放内存");
    free(valueOrigin);
    free(cipherText);
    free(desText);

    return cipher;
}

JNIEXPORT jbyteArray JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_decodeByRSAPubKey(JNIEnv *env, jobject instance,
                                                                 jbyteArray keys_,
                                                                 jbyteArray value_) {
    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(value_, NULL);
    jsize src_Len = env->GetArrayLength(value_);

    int ret = 0, src_flen = 0, plaintext_offset = 0, desText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    LOGI("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(keys, -1);
    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    desText_len = (flen - 11) * (src_Len / flen + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *plaintext = (unsigned char *) malloc(flen - 11);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

    LOGI("RSA->对数据进行公钥解密运算");
    //一次性解密数据最大字节数RSA_size
    for (int i = 0; i <= src_Len / flen; i++) {
        src_flen = (i == src_Len / flen) ? src_Len % flen : flen;
        if (src_flen == 0) {
            break;
        }

        memset(plaintext, 0, flen - 11);
        ret = RSA_public_decrypt(src_flen, srcOrigin + src_offset, plaintext, rsa,
                                 RSA_PKCS1_PADDING);

        memcpy(desText + plaintext_offset, plaintext, ret);
        plaintext_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(value_, src, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_offset);
    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, plaintext_offset, (jbyte *) desText);
    LOGI("RSA->释放内存");
    free(srcOrigin);
    free(plaintext);
    free(desText);

    return cipher;
}

JNIEXPORT jbyteArray JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_decodeByRSAPrivateKey(JNIEnv *env,
                                                                     jobject instance,
                                                                     jbyteArray keys_,
                                                                     jbyteArray value_) {
    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *value = env->GetByteArrayElements(value_, NULL);
    jsize value_len = env->GetArrayLength(value_);

    int ret = 0, value_flen = 0, plaintext_offset = 0, descText_len = 0, value_offset = 0;
    RSA *rsa = NULL;
    BIO *keybio = NULL;

    LOGI("RSA->从字符串读取RSA私钥");
    keybio = BIO_new_mem_buf(keys, -1);
    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    descText_len = (flen - 11) * (value_len / flen + 1);

    unsigned char *valueOrigin = (unsigned char *) malloc(value_len);
    unsigned char *plainText = (unsigned char *) malloc(flen - 11);
    unsigned char *desText = (unsigned char *) malloc(descText_len);
    memset(desText, 0, descText_len);

    memset(valueOrigin, 0, value_len);
    memcpy(valueOrigin, value, value_len);

    LOGI("RSA->对数据进行私钥解密运算");
    //一次性解密数据最大字节数RSA_size
    for (int i = 0; i <= value_len / flen; ++i) {
        value_flen = (i == value_len / flen) ? value_len % flen : flen;
        if (value_flen == 0) {
            break;
        }

        memset(plainText, 0, flen - 11);
        ret = RSA_private_decrypt(value_flen, valueOrigin + value_offset, plainText, rsa,
                                  RSA_PKCS1_PADDING);
        memcpy(desText + plaintext_offset, plainText, ret);
        plaintext_offset += ret;
        value_offset += value_flen;
    }

    RSA_free(rsa);
    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(value_, value, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_offset);
    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, plaintext_offset, (const jbyte *) desText);
    LOGI("RSA->释放内存");
    free(valueOrigin);
    free(plainText);
    free(desText);

    return cipher;
}

JNIEXPORT jbyteArray JNICALL
Java_com_guoyang_android_openssl_util_JniUtils_encodeByRSAPrivateKey(JNIEnv *env,
                                                                     jobject instance,
                                                                     jbyteArray keys_,
                                                                     jbyteArray value_) {
    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *value = env->GetByteArrayElements(value_, NULL);
    jsize value_len = env->GetArrayLength(value_);

    int ret = 0, value_flen = 0, cipherText_offset = 0, desText_len = 0, value_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    LOGI("RSA->从字符串读取RSA私钥");
    keybio = BIO_new_mem_buf(keys, -1);
    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    desText_len = flen * (value_len / (flen - 11) + 1);

    unsigned char *valueOrigin = (unsigned char *) malloc(value_len);
    unsigned char *cipherText = (unsigned char *) malloc(flen);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    memset(valueOrigin, 0, value_len);
    memcpy(valueOrigin, value, value_len);

    LOGI("RSA->对数据进行私钥加密运算");
    for (int i = 0; i <= value_len / (flen - 11); ++i) {
        value_flen = (i == value_len / (flen - 11)) ? value_len % (flen - 11) : flen - 11;
        if (value_flen == 0) {
            break;
        }

        memset(cipherText, 0, flen);
        ret = RSA_private_encrypt(value_flen, valueOrigin + value_offset, cipherText, rsa,
                                  RSA_PKCS1_PADDING);

        memcpy(desText + cipherText_offset, cipherText, ret);
        cipherText_offset += ret;
        value_offset += value_flen;
    }

    RSA_free(rsa);
    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(value_, value, 0);
    jbyteArray cipher = env->NewByteArray(cipherText_offset);
    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (const jbyte *) desText);
    LOGI("RSA->释放内存");
    free(valueOrigin);
    free(cipherText);
    free(desText);

    return cipher;
}
}
