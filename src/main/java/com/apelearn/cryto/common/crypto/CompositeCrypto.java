package com.apelearn.cryto.common.crypto;


import com.apelearn.cryto.common.crypto.util.CharsetUtil;
import com.apelearn.cryto.common.crypto.util.RadixUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 一个加密解密的好用工具类，可以组合多种加密解密方式
 * 这个就能很好地表达先进行什么加密再进行什么加密，自动逆序解密
 * @author 熊诗言
 */
public class CompositeCrypto implements Crypto {
    private List<Crypto> cryptos = null;
    /**
     * true 字符串-字节-...-字节-字符串
     * false 字符串-字符串-...-字符串-字符串
     */
    private boolean byteTransfer = false;

    public CompositeCrypto(Crypto... cryptos){
        this.cryptos = new ArrayList<>(cryptos.length);
        this.cryptos.addAll(Arrays.asList(cryptos));
    }

    /**
     * 添加加密解密器，注意顺序
     * @param crypto Crypto
     * @return CompositeCrypto
     */
    public CompositeCrypto add(Crypto crypto){
        cryptos.add(crypto);
        return this;
    }

    public List<Crypto> getCryptos() {
        return cryptos;
    }

    public void setCryptos(List<Crypto> cryptos) {
        this.cryptos = cryptos;
    }

    public boolean isByteTransfer() {
        return byteTransfer;
    }

    public CompositeCrypto setByteTransfer(boolean byteTransfer) {
        this.byteTransfer = byteTransfer;
        return this;
    }

    @Override
    public byte[] encrypt(byte[] src) {
        byte[] result = src;
        try {
            for (Crypto crypto : cryptos) {
                result = crypto.encrypt(result);
            }
        } catch (Exception e) {
            throw new CryptoException(e);
        }
        return result;
    }

    @Override
    public byte[] decrypt(byte[] src) {
        int len = cryptos.size();
        byte[] result = src;
        try {
            for (int i = len-1; i >= 0; i--) {
                result = cryptos.get(i).decrypt(result);
            }
        } catch (Exception e) {
            throw new CryptoException(e);
        }
        return result;
    }

    /**
     * 按照添加顺序加密
     * @param src 源加密串
     */
    @Override
    public String encrypt(String src, String charset) {
        if(null == src){return null;}
        if(byteTransfer){
            byte[] bytes = src.getBytes(CharsetUtil.charset(charset));
            byte[] encrypt = encrypt(bytes);
            return RadixUtil.toHex(encrypt);
        }else {
            return stringEnc(src, charset, cryptos);
        }
    }


    @Override
    public String encrypt(String src) throws CryptoException{
        return encrypt(src, CharsetUtil.UTF_8);
    }

    private String stringEnc(String src, String charset , List<Crypto> cryptos) {
        String result = src;
        try {
            for (Crypto crypto : cryptos) {
                result = crypto.encrypt(result ,charset);
            }
        } catch (Exception e) {
            throw new CryptoException(e);
        }
        return result;
    }

    /**
     * 逆序解密
     * @param src 原字符串
     * @param charset 返回的字符串编码
     */
    @Override
    public String decrypt(String src, String charset) {
        if(null == src){return null;}
        if(byteTransfer){
            byte[] bytes = RadixUtil.toBytes(src);
            byte[] decrypted = decrypt(bytes);
            return new String(decrypted , CharsetUtil.charset(charset));
        }else {
            return stringDec(src, CharsetUtil.UTF_8, cryptos);
        }
    }

    @Override
    public String decrypt(String src) throws CryptoException{
        return decrypt(src , CharsetUtil.UTF_8);
    }

    private String stringDec(String src, String charset , List<Crypto> cryptos){
        int len = cryptos.size();
        String result = src;
        try {
            for (int i = len-1; i >= 0; i--) {
                result = cryptos.get(i).decrypt(result,charset);
            }
        } catch (Exception e) {
            throw new CryptoException(e);
        }
        return result;
    }
}
