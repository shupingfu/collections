package com.shuping.collections.util;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 随机
 *
 * @author shuping
 * @date 2021/12/10
 */
public class RandomUtil {

    public static int randomInt(int boundary) {
        // Random线程安全，CAS算法，高并发下可能浪费cpu
//        Random random = new Random();
//        return random.nextInt(boundary);
        // 使用ThreadLocalRandom 前闭后开
        return ThreadLocalRandom.current().nextInt(boundary);
    }


    static Random random = new Random();
    public static void main(String[] args) {
        long l = System.currentTimeMillis();

        for (int i = 0; i < 100000; i++) {
            new Thread(() ->{
//                int i1 = new Random().nextInt();
//                int i1 = random.nextInt();
                int i1 = ThreadLocalRandom.current().nextInt();
            }).start();
        }

        System.out.println(System.currentTimeMillis() - l);

        // 线程内的Random 8341 8485 8352
        // 静态Random 7653 7670 7471
        // ThreadLocalRandom 7516 7640 7488

    }

}
