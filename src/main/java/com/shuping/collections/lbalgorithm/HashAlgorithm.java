package com.shuping.collections.lbalgorithm;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * 哈希
 *
 * @description 负载均衡算法
 * @author shuping
 * @date 2021/12/10
 */
public class HashAlgorithm {

    static final List<String> serverList = Arrays.asList("192.168.1.100", "192.168.1.101", "192.168.1.102");

    public static void main(String[] args) {
        for (int i = 0; i < 100; i++) {
            String s = UUID.randomUUID().toString();
            String server = Hash.getServer(s);
            System.out.println(s + "===>>" + server);
        }
        // 有可能导致服务器倾斜严重

        //哈希算法（Hash）又称摘要算法（Digest），它的作用是：对任意一组输入数据进行计算，得到一个固定长度的输出摘要。目的是为了验证原始数据是否被篡改
        //哈希算法最重要的特点就是：
        //  相同的输入一定得到相同的输出；
        //  不同的输入大概率得到不同的输出。
        //哈希算法的目的就是为了验证原始数据是否被篡改。
        // md5/sha-256/sha-512 均属于哈希算法，
    }

}

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