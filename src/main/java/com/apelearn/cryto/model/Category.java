package com.apelearn.cryto.model;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;


@Data
public class Category {

    @ApiModelProperty("ID")
    private String id;

    @ApiModelProperty("分类名称")
    private String categoryName;

    @ApiModelProperty("创建时间")
    private Long createTime;

    @ApiModelProperty("创建用户ID")
    private Long createUserId;
}