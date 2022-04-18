package com.pepsiwyl.pojo;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.*;
import org.apache.ibatis.type.Alias;

/**
 * @author by pepsi-wyl
 * @date 2022-04-17 20:15
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode

@Alias("user")

@TableName(schema = "jwt", value = "user")
public class User {

    @TableId
    private String id;

    private String name;

    private String password;

}
