package com.apelearn.cryto.model;

import lombok.Data;


@Data
public class Category {
    private String id;

    private String categoryName;

    private Long createTime;

    private Long createUserId;
}