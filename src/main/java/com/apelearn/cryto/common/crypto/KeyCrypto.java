package com.apelearn.cryto.common.crypto;

/**
 * 对于那些需要设置key的
 * @author 熊诗言
 * @see Crypto
 */
public interface KeyCrypto extends Crypto {
    /**
     * 设置key,并返回自己
     * @param key key
     * @return this
     */
    KeyCrypto setKey(String key);
}