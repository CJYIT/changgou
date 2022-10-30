package com.changgou.user.feign;

import com.changgou.user.pojo.User;
import entity.Result;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

/****
 * @Author:cjy
 * @Description: com.changgou.user.feign
 * @Date
 *****/
@FeignClient(name = "user")  //注意feign的名字name不是value
@RequestMapping(value = "/user")
public interface UserFeign {
    //把需要调用的方法拷贝过来

    /**
     * 根据id查询用户信息
     * @param id
     * @return
     */
    @GetMapping({"/load/{id}"})  //然后到ResourceServerConfig配置
    Result<User> findById(@PathVariable String id);
}
