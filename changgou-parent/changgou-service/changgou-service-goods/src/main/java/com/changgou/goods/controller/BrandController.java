package com.changgou.goods.controller;

import com.changgou.goods.pojo.Brand;
import com.changgou.goods.service.BrandService;
import com.github.pagehelper.PageInfo;
import entity.Result;
import entity.StatusCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 描述
 *
 * @author 三国的包子
 * @version 1.0
 * @package com.changgou.goods.controller *
 * @since 1.0
 */
@RestController
@RequestMapping("/brand")
public class BrandController {

    @Autowired
    private BrandService brandService;//调用service，将service注入

//    根据分类id查询品牌集合    分类id
@GetMapping(value = "/category/{id}")
public Result<List<Brand>> findBrandByCategory(@PathVariable(value = "id")Integer categoryId){
    //调用Service查询品牌数据
    List<Brand> categoryList = brandService.findByCategory(categoryId);
    return new Result<List<Brand>>(true,StatusCode.OK,"查询成功！",categoryList);
}

    /**
     * url:/brand
     * 参数: 没有
     * 返回值: json   result<List<Brand>>
     *
     * @return
     */
    @GetMapping
    public Result<List<Brand>> findAll() {
        try {
            System.out.println("睡觉时间到"+Thread.currentThread().getId());
            Thread.sleep(1000);
            System.out.println("赶紧睡觉"+Thread.currentThread().getId());
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        List<Brand> all = brandService.findAll();
        return new Result<List<Brand>>(true, StatusCode.OK, "查询成功", all);
    }



    /**
     *  //根据品牌的主键查询品牌的数据返回
     * @param id
     * @return
     */
    @GetMapping("/{id}")
    public Result<Brand>  findById(@PathVariable(name="id") Integer id){
        //@PathVariable获取请求路径中的一部分并且收取出来作为一个变量
        Brand brand =   brandService.findById(id);
        return new Result<Brand>(true,StatusCode.OK,"查询品牌成功",brand);
    }

    /**
     * 添加品牌数据
     * @param brand
     * @return
     */
    @PostMapping
    public Result add(@RequestBody Brand brand){//json格式接收数据转对象使用@RequestBody
//        调用service实现增加操作
        brandService.add(brand);
        return new Result<>(true, StatusCode.OK, "添加成功");//返回添加成功状态提示
    }

    /**
     *  根据ID 更新品牌的数据
     * @param brand 请求体 更新后的数据
     * @param id 要修改的品牌的ID
     * @return
     * 前端的数据是json格式使用@RequestBody注解
     */
    @PutMapping("/{id}")
    public Result update(@RequestBody Brand brand,@PathVariable(value="id")Integer id){
//        将id给brand
        brand.setId(id);
        brandService.update(brand);
        return new Result(true,StatusCode.OK,"更新成功");
    }

    @DeleteMapping("/{id}")
    public Result delete(@PathVariable(value="id") Integer id){
        brandService.delete(id);
        return new Result(true,StatusCode.OK,"删除成功");
    }

    /**
     *
     * @param brand
     * @return
     */
    @PostMapping("/search")
    public Result<List<Brand>> findList(@RequestBody  Brand brand){//@RequestBody  Brand brand前端提交的参数转成brand
       List<Brand> brands =  brandService.findList(brand);
        return new Result(true,StatusCode.OK,"条件查询成功",brands);
    }

    /**
     *  分页查询
     * @param page 当前页
     * @param size 每页显示的行
     * @return
     */
    @GetMapping("/search/{page}/{size}")
    public Result<PageInfo<Brand>> findPage(@PathVariable(value="page")Integer page,@PathVariable(value="size") Integer size){
        PageInfo<Brand> info = brandService.findPage(page,size);
        return new Result<PageInfo<Brand>>(true,StatusCode.OK,"分页查询成功",info);
    }

    /**
     * 根据条件 来分页查询
     * @param page
     * @param size
     * @param brand 添加对象(请求体)
     * @return
     */
    @PostMapping("/search/{page}/{size}")
    public Result<PageInfo<Brand>> findPage(@PathVariable(value="page")Integer page,@PathVariable(value="size") Integer size,@RequestBody  Brand brand){
        PageInfo<Brand> info = brandService.findPage(page,size,brand);
        int i=1/0;
        return new Result<PageInfo<Brand>>(true,StatusCode.OK,"分页查询成功",info);
    }
}
