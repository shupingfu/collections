package com.shuping.collections.lbalgorithm;

import com.shuping.collections.util.RandomUtil;

import java.util.*;

/**
 * 完全随机，加权随机
 *
 * @description 负载均衡算法
 * @author shuping
 * @date 2021/12/10
 */
public class RandomAlgorithm {

    // 完全随机算法
    static final List<String> serverList = Arrays.asList("192.168.1.100", "192.168.1.101", "192.168.1.102");

    // 加权随机算法
    static final Map<String, Integer> serverWeightList = new HashMap<String, Integer>() {{
        put("192.168.1.100", 1);
        put("192.168.1.101", 2);
        put("192.168.1.102", 3);
        put("192.168.1.103", 4);
    }};

    public static void main(String[] args) {
        // 4.完全随机算法
//        for (int i = 0; i < 100; i++) {
//            new Thread(() -> {
//                String server = Random.getServer();
//                System.out.println(server);
//            }).start();
//        }

        // 5.加权随机算法
        for (int i = 0; i < 100; i++) {
            new Thread(() -> {
                String server = RandomWeight.getServer();
                System.out.println(server);
            }).start();
        }
    }

}

/**
 * 完全随机
 */
class Random {
    public static String getServer() {
        int i = RandomUtil.randomInt(RandomAlgorithm.serverList.size());
        return RandomAlgorithm.serverList.get(i);
    }
}

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