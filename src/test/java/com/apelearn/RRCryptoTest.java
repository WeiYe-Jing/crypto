package com.apelearn;

import com.apelearn.cryto.common.crypto.Crypto;
import com.apelearn.cryto.common.crypto.symmetric.AesCrypto;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


/**
 * test
 *
 */

public class RRCryptoTest {
    /**
     * 加密解密方式使用一样的
     */
    public static void main(String[] args) {
        Crypto crypto = new AesCrypto("dsfsdgwaregw");
        System.out.println(crypto.encrypt("{\"categoryName\":\"蔬菜\",\n" +
                "\t\"id\":\"123456\",\n" +
                "\t\"createTime\":\"1571626606\"\n" +
                "}\n"));
        System.out.println(crypto.decrypt("YTi7rgNkDjM1poXA/+ENOVnWXtXf61/KcbGX/08SsOVm1iHoGpBkjqLu4f6UX2oKUFgHOLLdY83B4tAy4YZxF+RwDDXnYbM73f0AxTi71XQ="));
    }
}