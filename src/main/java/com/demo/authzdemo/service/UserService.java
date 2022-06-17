package com.demo.authzdemo.service;

import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserEntity processOAuthPostLogin(String username) {
        var user = userRepository.getUserByUsername(username);

        if (user == null) {
            user=new UserEntity();
            user.setUsername(username);
            user.setEnabled(true);
            userRepository.save(user);
        }

        return user;
    }
}
