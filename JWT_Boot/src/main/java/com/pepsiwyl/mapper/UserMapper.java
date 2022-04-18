package com.pepsiwyl.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.pepsiwyl.pojo.User;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author by pepsi-wyl
 * @date 2022-04-17 20:18
 */

@Transactional

@Mapper
public interface UserMapper extends BaseMapper<User> {

}
