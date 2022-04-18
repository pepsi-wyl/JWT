![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650182563625-f217ecae-754c-44c2-891d-ed3a062dcaa8.png#clientId=u4deb50b4-0fef-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=470&id=u3ab191d7&margin=%5Bobject%20Object%5D&name=image.png&originHeight=470&originWidth=1254&originalType=binary&ratio=1&rotation=0&showTitle=false&size=54341&status=done&style=none&taskId=ube83bc94-d60a-4519-9702-ede17e330cc&title=&width=1254)![image-20200726102546868.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650184725950-9794a7af-613a-4c36-b739-e398c9ed1315.png#clientId=ua8da8053-b8d2-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=u35e28a2d&margin=%5Bobject%20Object%5D&name=image-20200726102546868.png&originHeight=372&originWidth=2434&originalType=binary&ratio=1&rotation=0&showTitle=false&size=50976&status=done&style=none&taskId=u9efbea18-4330-47f6-b668-276fc61911c&title=)
<a name="r3kjc"></a>
# 简介[官网](https://jwt.io/introduction/)
<a name="WQ6m0"></a>
## JWT是什么
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650184917697-4a345124-21f6-4ef4-8907-453d4e7a2244.png#clientId=ub2f1fc14-e8d0-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=163&id=u65770f2b&margin=%5Bobject%20Object%5D&name=image.png&originHeight=163&originWidth=557&originalType=binary&ratio=1&rotation=0&showTitle=false&size=17175&status=done&style=none&taskId=ue909c9e5-bc60-421b-9f81-5aa429b3f14&title=&width=557)
```markdown
- jsonwebtoken（JWT）是一个开放标准（rfc7519），它定义了一种紧凑
- 的、自包含的方式，用于在各方之间以JSON对象安全地传输信息。此信息
- 可以验证和信任，因为它是数字签名的。jwt可以使用秘密（使用HMAC算
- 法）或使用RSA或ECDSA的公钥/私钥对进行签名

- JWT简称JSON Web Token,也就是通过JSON形式作为Web应用中的令牌,用
- 于在各方之间安全地将信息作为JSON对象传输。在数据传输过程中还可以
- 完成数据加密、签名等相关处理。
```
<a name="638a31ee"></a>
## JWT能做什么
```markdown
# 1.授权
- 这是使用JWT的最常见方案。一旦用户登录，每个后续请求将包括JWT，
- 从而允许用户访问该令牌允许的路由，服务和资源。
- 单点登录是当今广泛使用JWT的一项功能，因为它的开销很小并且可以在
- 不同的域中轻松使用。

# 2.信息交换
- JSON Web Token是在各方之间安全地传输信息的好方法。因为可以对
- JWT进行签名（例如，使用公钥/私钥对），所以您可以确保发件人是他
- 们所说的人。此外，由于签名是使用标头和有效负载计算的，因此您还可
- 以验证内容是否遭到篡改。
```
<a name="1f472eb2"></a>
## 为什么是JWT
<a name="f083b4bc"></a>
### 基于Session认证
<a name="pcyUY"></a>
#### 认证方式
http协议本身是一种无状态的协议，而这就意味着如果用户向我们的应用提供了用户名和密码来进行用户认证，那么下一次请求时，用户还要再一次进行用户认证才行，因为根据http协议，我们并不能知道是哪个用户发出的请求，所以为了让我们的应用能识别是哪个用户发出的请求，我们只能在服务器存储一份用户登录的信息，这份登录信息会在响应时传递给浏览器，告诉其保存为cookie,以便下次请求时发送给我们的应用，这样我们的应用就能识别请求来自哪个用户了,这就是传统的基于session认证。
<a name="GOoBU"></a>
#### 认证流程
![image-20200726103959013.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650185511658-abdad5e4-2904-454d-99fc-319a0ab31b1f.png#clientId=ub2f1fc14-e8d0-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=u69a67aaa&margin=%5Bobject%20Object%5D&name=image-20200726103959013.png&originHeight=268&originWidth=2116&originalType=binary&ratio=1&rotation=0&showTitle=false&size=50636&status=done&style=none&taskId=ue3dfc8b6-c8ac-4027-aad3-d5167d6d6da&title=)
<a name="wnpTc"></a>
#### 暴露问题

- 每个用户经过我们的应用认证之后，我们的应用都要在服务端做一次记录，以方便用户下次请求的鉴别，通常而言session都是保存在内存中，而随着认证用户的增多，服务端的开销会明显增大
- 用户认证之后，服务端做认证记录，如果认证的记录被保存在内存中的话，这意味着用户下次请求还必须要请求在这台服务器上,这样才能拿到授权的资源，这样在分布式的应用上，相应的限制了负载均衡器的能力。这也意味着限制了应用的扩展能力。
- 前后端分离在应用解耦后增加了部署的复杂性。通常用户一次请求就要转发多次。如果用session 每次携带sessionid 到服务器，服务器还要查询用户信息。同时如果用户很多。这些信息存储在服务器内存中，给服务器增加负担。还有就是CSRF（跨站伪造请求攻击）攻击，session是基于cookie进行用户识别的, cookie如果被截获，用户就会很容易受到跨站请求伪造的攻击。还有就是sessionid就是一个特征值，表达的信息不够丰富。不容易扩展。而且如果你后端应用是多节点部署。那么就需要实现session共享机制。不方便集群应用。
<a name="nCZYR"></a>
### ![image-20200804212240422.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650186640174-270fe409-e7d0-4db8-bea9-06b9e66e0340.png#clientId=ub2f1fc14-e8d0-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=udf87d7ee&margin=%5Bobject%20Object%5D&name=image-20200804212240422.png&originHeight=480&originWidth=2446&originalType=binary&ratio=1&rotation=0&showTitle=false&size=159811&status=done&style=none&taskId=u09a9e9cc-75e2-4a78-af10-b44489ce86a&title=)
<a name="c99bfd87"></a>
### 基于JWT认证
<a name="fHHMR"></a>
#### 认证流程
![image-20200726183248298.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650186724252-8cbb5f10-7a7a-4dcc-9bec-fea20e4be7f1.png#clientId=ub2f1fc14-e8d0-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=ue78c12aa&margin=%5Bobject%20Object%5D&name=image-20200726183248298.png&originHeight=942&originWidth=2410&originalType=binary&ratio=1&rotation=0&showTitle=false&size=165527&status=done&style=none&taskId=ube585716-19e1-469b-8230-b95bf5efe76&title=)

- 首先，前端通过Web表单将自己的用户名和密码发送到后端的接口。这一过程一般是一个HTTP POST请求。建议的方式是通过SSL加密的传输（https协议），从而避免敏感信息被嗅探。
- 后端核对用户名和密码成功后，将用户的id等其他信息作为JWT Payload（负载），将其与头部分别进行Base64编码拼接后签名，形成一个JWT(Token)。

       形成的JWT就是一个形同lll.zzz.xxx的字符串。 （head.payload.singurater）

- 后端将JWT字符串作为登录成功的返回结果返回给前端。前端可以将返回的结果保存在localStorage或sessionStorage上，退出登录时前端删除保存的JWT即可。
- 前端在每次请求时将JWT放入HTTP Header中的Authorization位。(解决XSS和XSRF问题)  HEADER
- 后端检查是否存在，如存在验证JWT的有效性。例如，检查签名是否正确；检查Token是否过期；检查Token的接收方是否是自己（可选）。
- 验证通过后后端使用JWT中包含的用户信息进行其他逻辑操作，返回相应结果。
<a name="HoMWd"></a>
#### jwt优势

- 简洁(Compact): 可以通过URL，POST参数或者在HTTP header发送，因为数据量小，传输速度也很快
- 自包含(Self-contained)：负载中包含了所有用户所需要的信息，避免了多次查询数据库
- 因为Token是以JSON加密的形式保存在客户端的，所以JWT是跨语言的，原则上任何web形式都支持。
- 不需要在服务端保存会话信息，特别适用于分布式微服务。
<a name="VuCsd"></a>
# JWT结构
<a name="FMagO"></a>
## 令牌组成
```markdown
token string  ====>  header.payload.singnature     
- 1.标头(Header)
- 2.有效载荷(Payload)
- 3.签名(Signature)
- 因此，JWT通常如下所示:xxxxx.yyyyy.zzzzz   Header.Payload.Signature
```
<a name="PNc6R"></a>
## 三部分
<a name="YGWF2"></a>
### Header

- 标头通常由两部分组成：令牌的类型（即JWT）和所使用的签名算法，例如HMAC SHA256或RSA。

       它会使用 Base64编码组成 JWT 结构的第一部分。<br />注意:   Base64是一种编码，也就是说，它是可以被翻译回原来的样子来的。它并不是一种加密过程。
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
<a name="o7JE2"></a>
### Payload

- 令牌的第二部分是有效负载，其中包含声明。声明是有关实体（通常是用户）和其他数据的声明。同样的，它会使用Base64编码组成 JWT 结构的第二部分
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```
<a name="HaUOA"></a>
### Signature

- 前面两部分都是使用 Base64 进行编码的，即前端可以解开知道里面的信息。

       Signature 需要使用编码后的 header 和 payload 以及我们提供的一个密钥，然后使用 header 中指        定的签名算法（HS256）进行签名。签名的作用是保证 JWT 没有被篡改过<br />       例如: HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload),secret);
<a name="QFyRI"></a>
#### 签名目的

- 最后一步签名的过程，实际上是对头部以及负载内容进行签名，防止内容被窜改。

      如果有人对头部以及负载的内容解码之后进行修改，再进行编码，最后加上之前的签名组合形成新的JWT的话，那么服务器端会判断出新的头部和负载形成的签名和JWT附带上的签名是不一样的。如果要对新的头部和负载进行签名，在不知道服务器加密时用的密钥的话，得出来的签名也是不一样的。
<a name="hskWV"></a>
#### 信息安全问题

- 在这里大家一定会问一个问题：Base64是一种编码，是可逆的，那么我的信息不就被暴露了吗？
- 是的。所以，在JWT中，不应该在负载里面加入任何敏感的数据。在上面的例子中，我们传输的是用户的User ID。这个值实际上不是什么敏感内容，一般情况下被知道也是安全的。但是像密码这样的内容就不能被放在JWT中了。如果将用户的密码放在了JWT中，那么怀有恶意的第三方通过Base64解码就能很快地知道你的密码了。因此JWT适合用于向Web应用传递一些非敏感信息。JWT还经常用于设计用户认证和授权系统，甚至实现Web应用的单点登录。
<a name="iSEu1"></a>
## 合起来
![image-20200726181136113.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650192721305-757d3b79-7336-4c11-bd4c-267e76653351.png#clientId=ub2f1fc14-e8d0-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=uedc8b9f2&margin=%5Bobject%20Object%5D&name=image-20200726181136113.png&originHeight=722&originWidth=2612&originalType=binary&ratio=1&rotation=0&showTitle=false&size=1286836&status=done&style=none&taskId=u97d7f3c1-9252-47a1-833c-e67058474e7&title=)<br />![image-20200726124257203.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650192813850-6656d8f9-dc5a-4b67-981e-66923af097c3.png#clientId=ub2f1fc14-e8d0-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=ub6e4e2c0&margin=%5Bobject%20Object%5D&name=image-20200726124257203.png&originHeight=218&originWidth=2142&originalType=binary&ratio=1&rotation=0&showTitle=false&size=110142&status=done&style=none&taskId=u01a4ff4f-7f13-474c-b333-b5f2ce53b62&title=)

- 输出是三个由点分隔的Base64-URL字符串，可以在HTML和HTTP环境中轻松传递这些字符串，与基于XML的标准（例如SAML）相比，它更紧凑。
- 简洁(Compact) 可以通过URL, POST 参数或者在 HTTP header 发送，因为数据量小，传输速度快
- 自包含(Self-contained) 负载中包含了所有用户所需要的信息，避免了多次查询数据库
<a name="OCR60"></a>
# 使用JWT
<a name="AVKck"></a>
## 引入依赖
```xml
<!--引入jwt-->
<dependency>
  <groupId>com.auth0</groupId>
  <artifactId>java-jwt</artifactId>
  <version>3.19.1</version>
</dependency>
```
<a name="Fsazw"></a>
## 生成token
```java
@Slf4j
public class JWT_T {
    public static void main(String[] args) {
        HashMap<String, Object> map = new HashMap<>(); // header
        Calendar calendar = Calendar.getInstance();    // 过期时间
        calendar.add(Calendar.MINUTE, 10);     // 10分钟过期
        /**
        * 令牌的获取
        */
        String token = JWT.create()
            // 设置过期时间
            .withExpiresAt(calendar.getTime())
            // 设置头信息
            .withHeader(map)
            // 设置负载信息
            .withClaim("userId", 1001)
            .withClaim("userName", "pepsi-wyl")
            // 设置签名 密钥
            .sign(Algorithm.HMAC256("@#$%{^&*-&*)]k[{8{}")); 
        log.info(token);
    }
}

```

```markdown
- 生成结果
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NTAxOTU0OTMsInVzZXJOYW1lIjoicGVwc2ktd3lsIiwidXNlcklkIjoxMDAxfQ.sOQ9T3eeeswIW62XXjyLccnetpmcnSvjcmvh61ab0kI
```
<a name="N20OE"></a>
## 解析数据
```java
@Slf4j
public class JWT_T {
    public static void main(String[] args) {
        /**
         * 令牌的验证
         */
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NTAxOTU0OTMsInVzZXJOYW1lIjoicGVwc2ktd3lsIiwidXNlcklkIjoxMDAxfQ.sOQ9T3eeeswIW62XXjyLccnetpmcnSvjcmvh61ab0kI";
        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("@#$%{^&*-&*)]k[{8{}")).build();
        DecodedJWT verify = jwtVerifier.verify(token);
        // as...... 什么类型就需要得到什么类型
        log.info("userId", verify.getClaim("userId").asInt().toString());
        log.info("userName", verify.getClaim("userName").asString());
        log.info("过期时间", verify.getExpiresAt().toString());
    }
}
```
<a name="fDm5L"></a>
## 常见异常信息
```markdown
- SignatureVerificationException:				签名不一致异常
- TokenExpiredException:    						令牌过期异常
- AlgorithmMismatchException:						算法不匹配异常
- InvalidClaimException:								失效的payload异常
```
<a name="UUdIc"></a>
## JWTUtils
```java
public class JWTUtils {

    // 密钥
    private static final String SING = "f4e2e52034348f86b67cde581c0f9eb5";
    // 过期天数
    private static final Integer DAYS = 7;

    /**
     * 创建Token
     *
     * @param map 参数列表
     * @return
     */
    public static String getToken(Map<String, String> map) {
        // 创建 jwtBuilder
        JWTCreator.Builder builder = JWT.create();
        // payload
        map.forEach((k, v) -> {
            builder.withClaim(k, v);
        });
        // 过期时间
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, DAYS);
        builder.withExpiresAt(calendar.getTime());
        // 签名
        return builder.sign(Algorithm.HMAC256(SING));
    }

    /**
     * 获取Token 中 payload
     *
     * @param token
     * @return
     */
    public static DecodedJWT verifyToken(String token) {
        return JWT.require(Algorithm.HMAC256(SING)).build().verify(token);
    }
}
```
<a name="Yuw89"></a>
# 整合SpringBoot
<a name="SLeDd"></a>
## 准备工作
<a name="uJsXN"></a>
### Dependency
```java
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
 
        <!--yaml配置提示 configuration-processor -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
        </dependency>
```
<a name="ua8uC"></a>
### YAML
```yaml
server:
  port: 8888
  servlet:
    context-path: /
```
<a name="I6Q0S"></a>
## Mapper
<a name="kjz8I"></a>
### Database
```sql
create database jwt;
use jwt;

DROP TABLE IF EXISTS `user`;
CREATE TABLE `user`
(
    `id`       int(11) NOT NULL AUTO_INCREMENT COMMENT '主键',
    `name`     varchar(80) DEFAULT NULL COMMENT '用户名',
    `password` varchar(40) DEFAULT NULL COMMENT '用户密码',
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 2
  DEFAULT CHARSET = utf8;

insert into user value (1, 'pepsi-wyl', '000000');
```
<a name="Ruky9"></a>
### Dependency
```xml
        <!--JDBC-mysql驱动-->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>
        <!--druid-dataSource 场景启动器-->
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid-spring-boot-starter</artifactId>
            <version>1.2.8</version>
        </dependency>
        <!--mybatis - plus场景启动器 内置了 jdbc启动场景-->
        <dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-boot-starter</artifactId>
            <version>3.2.0</version>
        </dependency>

        <!--lombok插件简化Bean开发 @Slf4j日志打印-->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
```
<a name="UUoq4"></a>
### YAML
```yaml
spring:
  # 数据库配置信息
  datasource:
    username: root
    password: bsy8023.00
    url: jdbc:mysql://localhost:3306/jwt?useSSL=true&useUnicode=true&characterEncoding=utf8&serverTimezone=UTC&rewriteBatchedStatements=true
    driver-class-name: com.mysql.cj.jdbc.Driver
    # druid 数据库连接池
    type: com.alibaba.druid.spring.boot.autoconfigure.DruidDataSourceWrapper

# mybatis-plus 配置
mybatis-plus:
  configuration:
    # 日志配置信息
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl
  # 包扫描别名
  type-aliases-package: com.pepsiwyl.pojo
  # mapper文件
  mapper-locations: classpath*:/mapper/**/*.xml
```
<a name="hY614"></a>
### Config
```java
@Configuration
@EnableTransactionManagement
public class MybatisPlusConfig {

}
```
<a name="vhYmR"></a>
### POJO
User
```java
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
```
<a name="TejgC"></a>
### MapperInterface
UserMapper
```java
@Transactional

@Mapper
public interface UserMapper extends BaseMapper<User> {

}
```
<a name="UwsSE"></a>
### MapperXML
UserMapper.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.pepsiwyl.mapper.UserMapper">

</mapper>
```
<a name="iaVCr"></a>
## Service
<a name="BydE9"></a>
### ServiceInterface
UserService
```java
public interface UserService extends IService<User> {
    
}
```
<a name="tH3Um"></a>
### ServiceImpl
```java
@Transactional

@Service("userService")
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

}
```
<a name="pVWUl"></a>
## JWT
<a name="XHEii"></a>
### Dependency
```java
        <!--引入jwt-->
        <dependency>
            <groupId>com.auth0</groupId>
            <artifactId>java-jwt</artifactId>
            <version>3.19.1</version>
        </dependency>
```
<a name="jAc0y"></a>
### JWTUtils
```java
public class JWTUtils {

    // 密钥
    private static final String SING = "f4e2e52034348f86b67cde581c0f9eb5";
    // 过期天数
    private static final Integer DAYS = 7;

    /**
     * 创建Token
     *
     * @param map 参数列表
     * @return
     */
    public static String getToken(Map<String, String> map) {
        // 创建 jwtBuilder
        JWTCreator.Builder builder = JWT.create();
        // payload
        map.forEach((k, v) -> {
            builder.withClaim(k, v);
        });
        // 过期时间
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, DAYS);
        builder.withExpiresAt(calendar.getTime());
        // 签名
        return builder.sign(Algorithm.HMAC256(SING));
    }

    /**
     * 获取Token 中 payload
     *
     * @param token
     * @return
     */
    public static DecodedJWT verifyToken(String token) {
        return JWT.require(Algorithm.HMAC256(SING)).build().verify(token);
    }

}
```
<a name="Dy3tN"></a>
## Controller
<a name="D5ib2"></a>
### UserController
```java
@Slf4j

@RestController
@RequestMapping("/user")
public class UserController {

    @Resource(name = "userService")
    private UserService userService;

    @SneakyThrows
    @GetMapping("/login")
    public Map<String, Object> login(@RequestParam("name") String name, @RequestParam("password") String password) {
        log.info("username:" + name + " password:" + password);
        HashMap<String, Object> result = new HashMap<>();

        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("name", name).eq("password", password);
        User user = userService.getOne(wrapper);
        
        // 登陆成功
        if (user != null) {
            log.info(user.toString());
            // 生成JWTToken
            HashMap<String, String> payload = new HashMap<>();
            payload.put("id", user.getId());
            payload.put("name", user.getName());
            // Token
            String token = JWTUtils.getToken(payload);
            log.info(token);
            result.put("state", true);
            result.put("msg", "登录成功!!!");
            result.put("token", token);
            return result;
        }

        result.put("state", false);
        result.put("msg", "登录失败!!!");
        return result;
    }
}
```
<a name="QMXYG"></a>
### TestController
```java
@RestController
@RequestMapping("/test")
public class TestController {
    /**
     * 测试接口
     */
    @GetMapping("/test")
    public Map<String, Object> test(String token) {
        Map<String, Object> map = new HashMap<>();
        map.put("msg", "请求成功~~~");
        map.put("state", true);
        return map;
    }
}
```
<a name="zoccS"></a>
## Interceptor
<a name="hW8w9"></a>
### JwtTokenInterceptor
```java
// 拦截器
@Component("jwtTokenInterceptor")
public class JwtTokenInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String token = request.getHeader("authorization");  // 获取请求头信息
        Map<String, Object> map = new HashMap<>();
        try {
            // 验证token
            JWTUtils.verifyToken(token);
            
            return true;
        } catch (TokenExpiredException e) {
            map.put("state", false);
            map.put("msg", "Token已经过期!!!");
        } catch (SignatureVerificationException e) {
            map.put("state", false);
            map.put("msg", "签名错误!!!");
        } catch (AlgorithmMismatchException e) {
            map.put("state", false);
            map.put("msg", "加密算法不匹配!!!");
        } catch (Exception e) {
            e.printStackTrace();
            map.put("state", false);
            map.put("msg", "无效token~~");
        }
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().println(new ObjectMapper().writeValueAsString(map));
        return false;
    }
}
```
<a name="Ms9wH"></a>
### WebMVCConfig
```java
@Configuration
public class WebMVCConfig implements WebMvcConfigurer {

    // 注入拦截器
    @Resource(name = "jwtTokenInterceptor")
    JwtTokenInterceptor jwtTokenInterceptor;

    // 配置拦截器
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(jwtTokenInterceptor).
                excludePathPatterns("/user/**") // 放行路径
                .addPathPatterns("/**");      // 拦截路径
    }

}
```
<a name="MRwaF"></a>
## 截图
<a name="F9t8k"></a>
### 登陆成功
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650280757666-bf9a50f6-a54e-4dd6-80a1-6e4ba58481e1.png#clientId=u96eb2664-d5e3-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=539&id=uc034ad06&margin=%5Bobject%20Object%5D&name=image.png&originHeight=539&originWidth=888&originalType=binary&ratio=1&rotation=0&showTitle=false&size=57880&status=done&taskId=u8c190115-2476-4ac7-b725-afdf55b782a&title=&width=888)
<a name="Pj0BC"></a>
### 登陆失败
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650280721822-ada6df0e-d9c9-4d86-9d6b-5fa6fa116325.png#clientId=u96eb2664-d5e3-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=493&id=u9dbe88e3&margin=%5Bobject%20Object%5D&name=image.png&originHeight=493&originWidth=876&originalType=binary&ratio=1&rotation=0&showTitle=false&size=49039&status=done&style=none&taskId=uec3b987e-b2c5-4722-99f8-9da14e223d8&title=&width=876)
<a name="Idk7a"></a>
### 访问受限制资源
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650280662152-22100b61-e35e-42e2-84b6-40090dcef9e3.png#clientId=u96eb2664-d5e3-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=359&id=u99503347&margin=%5Bobject%20Object%5D&name=image.png&originHeight=359&originWidth=887&originalType=binary&ratio=1&rotation=0&showTitle=false&size=41803&status=done&style=none&taskId=u1dd3ead6-f82d-4077-b6d7-8124166cec1&title=&width=887)
