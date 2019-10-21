package com.apelearn.cryto.crypto;

import java.lang.annotation.*;

/**
 * 加密注解
 *
 * <p>加了此注解的接口(true)将进行数据加密操作
 *    可以放在类上，可以放在方法上 </p>
 * @author 熊诗言
 */
@Target({ElementType.METHOD , ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptResponse {
    /**
     * 是否对结果加密
     */
    boolean value() default true;
}