package com.apelearn.cryto.common.crypto.symmetric;


import com.apelearn.cryto.common.crypto.Crypto;
import com.apelearn.cryto.common.crypto.CryptoException;
import com.apelearn.cryto.common.crypto.util.CharsetUtil;

import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * URLEncoder 和 URLDecoder的加密解密方式
 * @author 熊诗言
 */
public class UrlCrypto implements Crypto {
    @Override
    public byte[] encrypt(byte[] src) {
        throw new CryptoException(new UnsupportedOperationException("请使用String encrypt(String src)"));
    }

    @Override
    public byte[] decrypt(byte[] src) {
        throw new CryptoException(new UnsupportedOperationException("请使用String decrypt(String src)"));
    }

    @Override
    public String encrypt(String src, String charset) {
        try {
            return URLEncoder.encode(src, charset);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public String encrypt(String src) {
        return encrypt(src, CharsetUtil.UTF_8);
    }

    @Override
    public String decrypt(String src, String charset) {
        try {
            return URLDecoder.decode(src, charset);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public String decrypt(String src) {
        return decrypt(src , CharsetUtil.UTF_8);
    }
}
