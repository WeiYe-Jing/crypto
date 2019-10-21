## 简介
服务端对输入输出参数进行加密处理


## 用法

#### 1.下载源码，修改数据库配置，启动
#### 2.加DecryptRequest 和 EncryptResponse 注解即可,可以放在Controller的类和方法上,其中一个为false就不执行了。像这样：

```
@Log4j2
@RestController
@Api(tags = "TestController", description = "测试")
@RequestMapping("/model")

@EncryptResponse
public class TestController {

    @DecryptRequest
    @ApiOperation("test")
    @RequestMapping(value = "/test", method = RequestMethod.POST)
    public CommonResult<Category> test(@RequestBody Category category) {
        log.info("分类名称" + category.getCategoryName());
        return CommonResult.success(category);
    }
}
```
#### 浏览器打开http://localhost:8089/doc.html
![](https://github.com/WeiYe-Jing/crypto/blob/master/img/20191021134827.png)
#### 后台输出日志
![](https://github.com/WeiYe-Jing/crypto/blob/master/img/20191021134225.png)


##### 参考文档:https://gitee.com/xxssyyyyssxx/affect-inoutput

