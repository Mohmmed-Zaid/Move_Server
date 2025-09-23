package com.moveapp.movebackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@EnableAsync
@EnableTransactionManagement
public class MovebackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(MovebackendApplication.class, args);
	}

}
