package com.shuping.collections.pinyin4j;

import net.sourceforge.pinyin4j.PinyinHelper;
import net.sourceforge.pinyin4j.format.HanyuPinyinCaseType;
import net.sourceforge.pinyin4j.format.HanyuPinyinOutputFormat;
import net.sourceforge.pinyin4j.format.HanyuPinyinToneType;
import net.sourceforge.pinyin4j.format.HanyuPinyinVCharType;
import net.sourceforge.pinyin4j.format.exception.BadHanyuPinyinOutputFormatCombination;

/**
 *
 * @description pinyin4j 中文（简体/繁体）转拼音
 * @author shuping
 * @date 2021/12/10
 */
public class Pinyin4j {

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

}
