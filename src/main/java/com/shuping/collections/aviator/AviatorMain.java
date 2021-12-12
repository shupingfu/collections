package com.shuping.collections.aviator;

import com.googlecode.aviator.AviatorEvaluator;
import com.googlecode.aviator.runtime.function.AbstractFunction;
import com.googlecode.aviator.runtime.function.FunctionUtils;
import com.googlecode.aviator.runtime.type.AviatorObject;
import com.googlecode.aviator.runtime.type.AviatorRuntimeJavaType;

import java.util.HashMap;
import java.util.Map;

/**
 * 轻量的表达式引擎
 *
 * @author shuping
 * @date 2021/12/12
 */
public class AviatorMain {

    public static void main(String[] args) {
        // 1、算术表达式
        Long result = (Long) AviatorEvaluator.execute("1 + 2 + 3");
        System.out.println(result); //6

        // 2、逻辑表达式
        Boolean result2 = (Boolean)AviatorEvaluator.execute("3>1 && 2!=4");
        System.out.println(result2);//true

        // 3、变量和字符串相加 变量默认为null
        Map<String, Object> env = new HashMap<>();
        env.put("name","shuping");
        String result3 = (String)AviatorEvaluator.execute(" 'hello ' + name ", env);
        System.out.println(result3);

        // 4、三元表达式 语法糖
        String result5=(String)AviatorEvaluator.execute("3>0 ? 'yes':'no'");
        System.out.println(result5);

        // 5、函数调用
        System.out.println(AviatorEvaluator.execute("string.length('hello')"));
        System.out.println(AviatorEvaluator.execute("string.contains('hello','h')"));
        System.out.println(AviatorEvaluator.execute("math.pow(-3,2)"));
        System.out.println(AviatorEvaluator.execute("math.sqrt(14.0)"));
        System.out.println(AviatorEvaluator.execute("math.sin(20)"));

        // 使用
        User user = new User();
        user.setName("shuping");
        user.setAge(25);

        HashMap<String, Object> userEnv = new HashMap<String, Object>() {{
            put("user", user);
        }};
        String expression = "string.length(user.name) > 0 && string.length(user.name) < 20 && user.age > 0 && user.age < 100";
        Object execute = AviatorEvaluator.execute(expression, userEnv, true);
        System.out.println(execute);

    }



}

class User {
    private String name;
    private Integer age;
    private String status;

    @Override
    public String toString() {
        return "User{" +
                "name='" + name + '\'' +
                ", age=" + age +
                ", status='" + status + '\'' +
                '}';
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getAge() {
        return age;
    }

    public void setAge(Integer age) {
        this.age = age;
    }
}

/**
 * 自定义函数
 */
class AviatorFunc extends AbstractFunction {

    public static void main(String[] args) {
        User user = new User();
        user.setName("shuping");
        user.setAge(25);

        HashMap<String, Object> userEnv = new HashMap<String, Object>() {{
            put("user", user);
        }};

        // 注册定义函数
        AviatorEvaluator.addFunction(new AviatorFunc());
        Object o = AviatorEvaluator.execute("aviatorFunc(user)", userEnv);
        User u = o instanceof User ? (User) o : null;
        System.out.println(u);
    }

    @Override
    public String getName() {
        return "aviatorFunc";
    }

    @Override
    public AviatorObject call(Map<String, Object> env, AviatorObject arg1) {
        Object o = FunctionUtils.getJavaObject(arg1, env);
        User user = o instanceof User ? (User) o : null;

        assert user != null;
        if (user.getName().length() > 0 && user.getName().length() < 20) {
            user.setStatus("合法");
        }
        user.setStatus(user.getName().length() > 0 && user.getName().length() < 20 ? "合法" : "不合法");
        return AviatorRuntimeJavaType.valueOf(user);
    }
}
