package com.apelearn.cryto.common.crypto.symmetric;


import com.apelearn.cryto.common.crypto.Crypto;
import com.apelearn.cryto.common.crypto.CryptoException;
import com.apelearn.cryto.common.crypto.util.CharsetUtil;
import com.apelearn.cryto.common.crypto.util.IoUtil;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Base64;

/**
 *  Base64加解密
 *  @author 熊诗言
 */
public class Base64Crypto implements Crypto {
    @Override
    public byte[] encrypt(byte[] src) {
        try {
            ///
            /*ByteArrayOutputStream out = new ByteArrayOutputStream();
            new BASE64Encoder().encode(src,out);
            return out.toByteArray();*/

            return Base64.getEncoder().encode(src);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] src) {
        try {
            /*ByteArrayInputStream in = new ByteArrayInputStream(src);
            return new BASE64Decoder().decodeBuffer(in);*/

            return Base64.getDecoder().decode(src);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public void encrypt(InputStream in, OutputStream out) {
        try {
            ///
            /*new BASE64Encoder().encodeBuffer(in,out);
            //什么区别？new BASE64Encoder().encode(in,out);*/

            byte[] bytes = IoUtil.stream2Bytes(in);
            byte[] encode = Base64.getEncoder().encode(bytes);
            out.write(encode);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public void decrypt(InputStream in, OutputStream out) {
        try {
            ///new BASE64Decoder().decodeBuffer(in,out);

            byte[] bytes = IoUtil.stream2Bytes(in);
            byte[] decode = Base64.getDecoder().decode(bytes);
            out.write(decode);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public String encrypt(String src, String charset) {
        ///return new BASE64Encoder().encodeBuffer(src.getBytes(CharsetUtil.charset(charset)) ).trim();
        return Base64.getEncoder().encodeToString(src.getBytes(CharsetUtil.charset(charset)));
    }

    @Override
    public String encrypt(String src){
        return encrypt(src, CharsetUtil.UTF_8);
    }

    @Override
    public String decrypt(String src, String charset) {
        ///
        /*try {
            return new String(new BASE64Decoder().decodeBuffer(src) , CharsetUtil.charset(charset)).trim();
        } catch (Exception e) {
            throw new CryptoException(e);
        }*/

        byte[] decode = Base64.getDecoder().decode(src);
        return new String(decode , CharsetUtil.charset(charset));
    }

    @Override
    public String decrypt(String src){
        return decrypt(src, CharsetUtil.UTF_8);
    }
}
