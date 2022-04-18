package com.pepsiwyl.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.pepsiwyl.mapper.UserMapper;
import com.pepsiwyl.pojo.User;
import com.pepsiwyl.service.UserService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author by pepsi-wyl
 * @date 2022-04-17 20:21
 */

@Transactional

@Service("userService")
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

}