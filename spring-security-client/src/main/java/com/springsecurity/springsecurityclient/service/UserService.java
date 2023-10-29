package com.springsecurity.springsecurityclient.service;

import com.springsecurity.springsecurityclient.entity.User;
import com.springsecurity.springsecurityclient.model.UserModel;
import org.springframework.stereotype.Service;

public interface UserService {
    User registerUser(UserModel userModel);

    void saveVerificationToken(String token, User user);

    String validateVerificationToken(String token);
}
