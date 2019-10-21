package com.apelearn.cryto.common.crypto.digest;


import com.apelearn.cryto.common.crypto.Crypto;
import com.apelearn.cryto.common.crypto.CryptoException;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * @author xiongshiyan at 2017/12/6
 */
public abstract class AbstractDigestCrypto implements Crypto {
    @Override
    final public byte[] decrypt(byte[] src) {
        unsupported();
        return null;
    }

    @Override
    final public String decrypt(String src){
        unsupported();
        return null;
    }

    @Override
    final public String decrypt(String src, String charset) {
        unsupported();
        return null;
    }

    @Override
    final public void decrypt(InputStream in, OutputStream out) {
        unsupported();
    }
    private void unsupported(){
        throw new CryptoException(new UnsupportedOperationException("摘要算法不支持解密，单向的"));
    }
}
