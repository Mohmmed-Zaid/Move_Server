package com.moveapp.movebackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@EnableAsync
@EnableJpaAuditing
@EnableTransactionManagement
public class MovebackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(MovebackendApplication.class, args);
	}

}
