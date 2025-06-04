package com.sample.task.authapp.controller;

import com.sample.task.authapp.model.User;
import com.sample.task.authapp.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api")
public class AuthController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public User register(@RequestBody User user) {
        return userService.register(user);
    }

    @GetMapping("/user")
    public User getUserDetails(Principal principal) {
        return userService.findByUsername(principal.getName());
    }

    @PostMapping("/logout")
    public void logout() {
    }
}

