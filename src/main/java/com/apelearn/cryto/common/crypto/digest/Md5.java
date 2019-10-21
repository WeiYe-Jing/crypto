package com.apelearn.cryto.common.crypto.digest;



import com.apelearn.cryto.common.crypto.Crypto;
import com.apelearn.cryto.common.crypto.CryptoException;

import java.security.MessageDigest;

/**
 * MD5加密
 * @author 熊诗言
 */
public class Md5 extends AbstractDigestCrypto implements Crypto {
    @Override
    public byte[] encrypt(byte[] src) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            return md5.digest(src);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }
}
