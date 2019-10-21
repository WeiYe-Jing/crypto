package com.apelearn.cryto.controller;

import com.apelearn.cryto.common.result.CommonResult;
import com.apelearn.cryto.crypto.DecryptRequest;
import com.apelearn.cryto.crypto.EncryptResponse;
import com.apelearn.cryto.model.Category;
import com.apelearn.cryto.service.CategoryService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


@Log4j2
@RestController
@Api(tags = "TestController", description = "测试")
@RequestMapping("/model")

@EncryptResponse
public class TestController {

    @Autowired
    private CategoryService CategoryService;

    @DecryptRequest
    @ApiOperation("test")
    @RequestMapping(value = "/test", method = RequestMethod.POST)
    public CommonResult<Category> test(@RequestBody Category category) {
        log.info("分类名称:" + category.getCategoryName());
        log.info("时间:"+category.getCreateTime());
        log.info("ID:"+category.getId());
        return CommonResult.success(category);
    }
}
