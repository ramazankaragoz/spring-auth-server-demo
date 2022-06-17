package com.demo.authzdemo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(value = "/")
public class HomeController {

    @GetMapping
    public ResponseEntity<String> home(HttpServletRequest request){
        return new ResponseEntity("Home...",HttpStatus.OK);
    }

}
