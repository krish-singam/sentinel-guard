package com.krish.sentinel_guard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SentinelGuardApplication {

	public static void main(String[] args) {
		SpringApplication.run(SentinelGuardApplication.class, args);
	}
}
