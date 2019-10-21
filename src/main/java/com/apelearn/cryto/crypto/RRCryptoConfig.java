package com.apelearn.cryto.crypto;

import com.apelearn.cryto.common.crypto.Crypto;
import com.apelearn.cryto.common.crypto.symmetric.AesCrypto;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


/**
 * Request-Response加解密体系的加解密方式
 * @author xiongshiyan at 2018/8/14 , contact me with email yanshixiong@126.com or phone 15208384257
 */
@Configuration
public class RRCryptoConfig {
    /**
     * 加密解密方式使用一样的
     */
    @Bean("rrCrypto")
    public Crypto rrCrypto(){
        return new AesCrypto("dsfsdgwaregw");
    }
}