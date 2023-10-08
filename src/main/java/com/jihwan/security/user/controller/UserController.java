package com.jihwan.security.user.controller;


import com.jihwan.security.user.entity.User;
import com.jihwan.security.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@RestController
public class UserController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;


    @PostMapping("/singup")
    public ResponseEntity<?> singup(@RequestBody User user){
        user.setUserPass(bCryptPasswordEncoder.encode(user.getUserPass()));
        user.setState("Y");
        User value = userRepository.save(user);
        String msg = "";
        if(Objects.isNull(value)){
            return ResponseEntity.ok(null);
        }else {
            return ResponseEntity.ok("가입완료");
        }
    }
}
