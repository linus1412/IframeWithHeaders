package com.example.iframewithheaders;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;

@SpringBootApplication
public class IframeWithHeadersApplication {

    public static void main(String[] args) {
        SpringApplication.run(IframeWithHeadersApplication.class, args);
    }

    @Controller
    public static class FramesController {

        @GetMapping("/")
        public String framer() {
            return "framer";
        }

        @GetMapping("/framee")
        public String framee(HttpServletRequest req, Model model) {

            var headerValue = req.getHeader("X-MADE-UP-HEADER");

            model.addAttribute("headerValue", headerValue);

            return "framee";
        }
    }

}
