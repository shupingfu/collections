package com.shuping.collections.lbalgorithm;

import java.util.*;

/**
 * 轮询，加权轮询
 *
 * @description 负载均衡算法
 * @author shuping
 * @date 2021/12/10
 */
public class RoundRobinAlgorithm {

    public static void main(String[] args) {
        // 加权轮询算法
//        for (int i = 0; i < 100; i++) {
//            new Thread(() -> {
//                String server = RoundRobinWeight.getServer();
//                System.out.println(server);
//            }).start();
//        }

        // 完全轮询算法
        for (int i = 0; i < 100; i++) {
            new Thread(() -> {
                String server = RoundRobin.getServer();
                System.out.println(server);
            }).start();
        }

        // 4.完全随机算法
        // 5.加权随机算法
        // 6.哈希负载算法
    }

}


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

class IpMap {
    // 待路由的Ip列表，Key代表Ip，Value代表该Ip的权重
    public static HashMap<String, Integer> serverWeightMap = new HashMap<>();

    static {
        // 加权轮询算法
//        serverWeightMap.put("192.168.1.100", 1); // 8
//        serverWeightMap.put("192.168.1.101", 4); // 32
//        serverWeightMap.put("192.168.1.102", 4);// 32
//        serverWeightMap.put("192.168.1.103", 4);// 28

        // 完全轮询 value不起作用
        serverWeightMap.put("192.168.1.100", 1); // 25
        serverWeightMap.put("192.168.1.101", 1); // 25
        serverWeightMap.put("192.168.1.102", 1); // 25
        serverWeightMap.put("192.168.1.103", 1); // 25
    }
}

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