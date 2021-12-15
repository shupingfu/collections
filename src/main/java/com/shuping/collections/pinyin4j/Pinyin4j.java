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

        System.out.println(PinyinHelper.toHanYuPinyinString("建 筑 工 程", format, " ", true));
        System.out.println(String.join(" ", "建筑工程技术".split("")));
        System.out.println(firsPinyin("建筑工程技术"));
    }

    /**
     * 获取中文拼音首字母大写
     *
     * @param chinese 中文
     * @return 全拼音首字母大写
     */
    private static String firsPinyin(String chinese) {
        HanyuPinyinOutputFormat format = new HanyuPinyinOutputFormat();
        format.setCaseType(HanyuPinyinCaseType.UPPERCASE);
        format.setToneType(HanyuPinyinToneType.WITHOUT_TONE);
        format.setVCharType(HanyuPinyinVCharType.WITH_U_AND_COLON);

        chinese = String.join(" ", chinese.split(""));
        String pinyin = null;
        try {
            pinyin = PinyinHelper.toHanYuPinyinString(chinese, format, "$", true);
        } catch (BadHanyuPinyinOutputFormatCombination badHanyuPinyinOutputFormatCombination) {
        }

        StringBuilder stringBuilder = new StringBuilder();
        if (pinyin != null) {
            char[] chars = pinyin.toCharArray();
            stringBuilder.append(chars[0]);
            for (int i = 0; i < chars.length; i++) {
                if (chars[i] == '$' && chars[i+1] == ' ') {
                    stringBuilder.append(chars[i + 2]);
                }
            }
        }
        return stringBuilder.toString();
    }

}
