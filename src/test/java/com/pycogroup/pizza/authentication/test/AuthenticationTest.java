package com.pycogroup.pizza.authentication.test;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.pycogroup.pizza.model.ERole;
import com.pycogroup.pizza.model.Role;
import com.pycogroup.pizza.model.User;
import com.pycogroup.pizza.authentication.repository.RoleRepository;
import com.pycogroup.pizza.authentication.repository.UserRepository;
import com.pycogroup.pizza.authentication.security.jwt.JwtUtils;
import com.pycogroup.pizza.authentication.security.service.UserDetailsImpl;
import com.pycogroup.pizza.authentication.security.service.UserDetailsServiceImpl;

@SpringBootTest
public class AuthenticationTest {

  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  UserDetailsServiceImpl userDetailsServiceImpl;

  @Autowired
  JwtUtils jwtUtils;

  @BeforeEach
  public void init() {
    roleRepository.save(new Role(ERole.ROLE_USER));
    Set<Role> roles = new HashSet<>();
    Role userRole = roleRepository.findByName(ERole.ROLE_USER).get();
    roles.add(userRole);
    User user = User.builder().firstName("Pheo").lastName("Chi")
         .birthDate("30/02/1900").address("1 Vu Dai vilage")
         .username("7777777").password(encoder.encode("loveyouno")).email("peacefulman@gmail.com")
         .roles(roles)
         .build();
    userRepository.save(user);
  }
  
  @AfterEach
  public void cleaning() {
    userRepository.deleteAll();
    roleRepository.deleteAll();
  }

  @DisplayName("authenticationUser test function")
  @Test
  public void authenticationUserTest() {

    // given
    String username = "7777777";
    String password = "loveyouno";

    // when 
    Authentication authenticationValid = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(username, password));

    UserDetailsImpl userDetails = (UserDetailsImpl) authenticationValid.getPrincipal();

    // then
    Assertions.assertTrue(userDetails.isEnabled());
    Assertions.assertEquals(userDetails.getUsername(),"7777777");
  }
  
}
