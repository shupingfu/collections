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

   

