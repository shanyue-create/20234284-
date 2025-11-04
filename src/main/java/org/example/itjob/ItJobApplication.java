package org.example.itjob;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@SpringBootApplication
@ServletComponentScan
public class ItJobApplication {

    public static void main(String[] args) {
        SpringApplication.run(ItJobApplication.class, args);
    }

}