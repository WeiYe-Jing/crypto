package com.apelearn.cryto.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * MyBatis配置类
 * Created by jwk on 2019/07/05.
 */
@Configuration
@EnableTransactionManagement
@MapperScan({"com.apelearn.cryto.mapper"})
public class MyBatisConfig {
}
