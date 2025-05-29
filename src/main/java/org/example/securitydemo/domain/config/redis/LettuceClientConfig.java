package org.example.securitydemo.domain.config.redis;

import io.lettuce.core.RedisClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LettuceClientConfig {

    @Value("${spring.data.redis.host}")
    private String redisHost;

    @Value("${spring.data.redis.port}")
    private int redisPort;

    /* 설명. 맥용 username, password */
//    @Value("${spring.data.redis.username}")
//    private String redisUsername;
//
//    @Value("${spring.data.redis.password}")
//    private String redisPassword;

//    @Bean
//    public RedisClient redisClient() {
//        String url = String.format("redis://%s:%s@%s:%d", redisUsername, redisPassword, redisHost, redisPort);
//        return RedisClient.create(url);
//    }
    @Bean
    public RedisClient redisClient() {
        String url = String.format("redis://%s:%d", redisHost, redisPort);
        return RedisClient.create(url);
    }
}