package com.dragon.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApplicationController {
    @RequestMapping(value = "/home")
    public String home(){
        return "Welcome Home";
    }
}
