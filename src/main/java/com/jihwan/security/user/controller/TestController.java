package com.jihwan.security.user.controller;


import org.springframework.security.access.prepost.PreAuthorize;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
@PreAuthorize("hasAnyAuthority('USER')")
public class TestController {

    @GetMapping
    public String tset(){
        return "test";
    }


    @PostMapping
    public String tset2(){
        return "test2";
    }
}
