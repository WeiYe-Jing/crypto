package com.apelearn.cryto.common.crypto;

/**
 * 加密解密有任何问题抛出该异常
 * @author 熊诗言
 */
public class CryptoException extends RuntimeException {
    public CryptoException(String message){
        super(message);
    }
    public CryptoException(Exception e){
        super(e);
    }
}
