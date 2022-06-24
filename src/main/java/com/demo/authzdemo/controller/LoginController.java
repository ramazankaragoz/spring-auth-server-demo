package com.demo.authzdemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {


    @GetMapping("/test-login/oauth2")
    public String login() {

        return "test-login";
    }

}
