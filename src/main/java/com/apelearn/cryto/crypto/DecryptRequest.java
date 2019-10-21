package com.apelearn.cryto.crypto;

import java.lang.annotation.*;

/**
 * 解密注解
 * 
 * <p>加了此注解的接口(true)将进行数据解密操作(post的body) 可
 *    以放在类上，可以放在方法上 </p>
 * @author xiongshiyan
 */
@Target({ElementType.METHOD , ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface DecryptRequest {
    /**
     * 是否对body进行解密
     */
    boolean value() default true;
}