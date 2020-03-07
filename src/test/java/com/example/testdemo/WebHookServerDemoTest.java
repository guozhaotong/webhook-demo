package com.example.testdemo;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;

import static com.example.testdemo.WebHookServerDemo.aesEncrypt;
import static com.example.testdemo.WebHookServerDemo.secret;

@RunWith(SpringRunner.class)
@SpringBootTest()
@WebAppConfiguration
public class WebHookServerDemoTest {
    Logger logger = LoggerFactory.getLogger(getClass());

    public MockMvc mockMvc;

    @Autowired
    protected WebApplicationContext wac;

    @Before()
    public void setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(wac).build();
    }

    @Test
    public void testGetNormal() throws Exception {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = String.valueOf(RandomUtils.nextLong());
        String originEcho = RandomStringUtils.randomAlphanumeric(5, 10);

        String echo = aesEncrypt(originEcho, secret);
        String signature = WebHookServerDemo.calculateSignature(Arrays.asList(timestamp, secret, nonce));

        logger.info("send signature:[{}], timestamp:[{}], nonce:[{}], echo:[{}]", signature, timestamp, nonce, echo);
        mockMvc.perform(MockMvcRequestBuilders.get("/any_path")
                .param("signature", signature)
                .param("timestamp", timestamp)
                .param("nonce", nonce)
                .param("echo", echo))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string(originEcho))
                .andDo(MockMvcResultHandlers.print());
    }

    @Test
    public void testGetError1() throws Exception {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = String.valueOf(RandomUtils.nextLong());
        String originEcho = RandomStringUtils.randomAlphanumeric(5, 10);
        String echo = aesEncrypt(originEcho, secret);
        String signature = "anything";
        logger.info("send signature:[{}], timestamp:[{}], nonce:[{}], echo:[{}]", signature, timestamp, nonce, echo);
        mockMvc.perform(MockMvcRequestBuilders.get("/any_path")
                .param("signature", signature)
                .param("timestamp", timestamp)
                .param("nonce", nonce)
                .param("echo", echo))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string("error"))
                .andDo(MockMvcResultHandlers.print());
    }

    @Test
    public void testPostNormal() throws Exception {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = String.valueOf(RandomUtils.nextLong());
        String signature = WebHookServerDemo.calculateSignature(Arrays.asList(timestamp, secret, nonce));
        String body = "{\"haha\":12312,\"你好\":\"不好\"}";
        logger.info("send signature:[{}], timestamp:[{}], nonce:[{}], body:[{}]", signature, timestamp, nonce, body);
        mockMvc.perform(MockMvcRequestBuilders.post("/any_path")
                .param("signature", signature)
                .param("timestamp", timestamp)
                .param("nonce", nonce)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json("{\"code\":0,\"msg\":\"ok\"}"))
                .andDo(MockMvcResultHandlers.print());
    }
}
