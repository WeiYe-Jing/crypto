package com.apelearn.cryto.common.result;

/**
 * 封装API的错误码
 * Created by jwk on 2019/07/05.
 */
public interface IErrorCode {
    long getCode();

    String getMessage();
}
