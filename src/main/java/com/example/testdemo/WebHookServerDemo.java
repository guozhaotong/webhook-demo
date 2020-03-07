package com.example.testdemo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

@SpringBootApplication
@RestController
public class WebHookServerDemo {

    Logger logger = LoggerFactory.getLogger(getClass());

    // 页面上配置的secret, secret一定是32位，算法是AES-256-ECB
    public static String secret = "hCnbLpVyunHWtdXShCnbLpVyunHWtdXS";

    public static void main(String[] args) {
        SpringApplication.run(WebHookServerDemo.class, args);
    }


    @GetMapping("/any_path")
    public String verifyUrl(String signature, long timestamp, long nonce, String echo) {
        logger.info("receive signature:[{}], timestamp:[{}], nonce:[{}], echo:[{}]", signature, timestamp, nonce, echo);

        // 验证是否是有数传过来的请求
        List<String> params = Arrays.asList(String.valueOf(timestamp), String.valueOf(nonce), secret);
        String localSignature = calculateSignature(params);
        if (!signature.equals(localSignature)) {
            return "error";
        }
        // 解密echo字符串，如果和有数发送的一样，则通过url验证。
        String result = aesDecrypt(echo, secret);
        logger.info("return:{}", result);
        return result;
    }

    @PostMapping(value = "/any_path", produces= "application/json")
    public WebHookResult send(@RequestParam String signature,
                              @RequestParam long timestamp,
                              @RequestParam long nonce,
                              @RequestBody String body) {
        logger.info("receive signature:[{}], timestamp:[{}], nonce:[{}], body:[{}]", signature, timestamp, nonce, body);
        // 验证是否是有数传过来的请求
        List<String> params = Arrays.asList(String.valueOf(timestamp), String.valueOf(nonce), secret);
        String localSignature = calculateSignature(params);
        if (!signature.equals(localSignature)) {
            return WebHookResult.of(2, "非法请求");
        }

        //处理自己的业务
        logger.info("do your service.");

        //返回正确响应
        return WebHookResult.of(0, "ok");
    }


    public static String calculateSignature(List<String> list) {
        // 字典序排序
        Collections.sort(list);
        // 拼接字符串
        String str = String.join("", list);
        // sha1加密
        return sha1(str);
    }

    public static String sha1(String inStr) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA");
            byte[] byteArray = inStr.getBytes(StandardCharsets.UTF_8);
            byte[] md5Bytes = sha.digest(byteArray);
            StringBuilder hexValue = new StringBuilder();
            for (byte md5Byte : md5Bytes) {
                int val = ((int) md5Byte) & 0xff;
                if (val < 16) {
                    hexValue.append("0");
                }
                hexValue.append(Integer.toHexString(val));
            }
            return hexValue.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public static String aesEncrypt(String content, String secret) {
        try {
            byte[] raw = secret.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            byte[] encrypted = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);//此处使用BASE64做转码功能
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static String aesDecrypt(String content, String secret) {
        try {
            byte[] bytes = Base64.getDecoder().decode(content);//先用base64解密
            byte[] raw = secret.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] doFinal = cipher.doFinal(bytes);
            return new String(doFinal, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}

// 用于返回调用结果
class WebHookResult {
    private int code;
    private String msg;

    private WebHookResult() {
    }

    public static WebHookResult of(int code, String msg) {
        WebHookResult result = new WebHookResult();
        result.code = code;
        result.msg = msg;
        return result;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }
}