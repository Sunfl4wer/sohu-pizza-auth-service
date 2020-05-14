package com.pycogroup.pizza.authentication.test;

import java.util.HashSet;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
  JwtUtils jwtUtils;
  
  @BeforeEach
  public void init() {
    roleRepository.save(new Role(ERole.ROLE_USER));
    Set<Role> roles = new HashSet<>();
    Role userRole = roleRepository.findByName(ERole.ROLE_USER).get();
    roles.add(userRole);
    User user = User.builder().firstName("Some").lastName("Name")
         .birthDate("30/02/1900").address("1 Ho Chi Minh")
         .username("7777777").password(encoder.encode("1234567")).email("peacefulman@gmail.com")
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
    String password = "1234567";

    // when 
    Authentication authenticationValid = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(username, password));

    UserDetailsImpl userDetails = (UserDetailsImpl) authenticationValid.getPrincipal();
    String userPasswordInDb = userRepository.findByUsername(username).get().getPassword();
    

    // then
    Assertions.assertTrue(userDetails.isEnabled());
    Assertions.assertEquals(userDetails.getUsername(),"7777777");
    Assertions.assertEquals("1 Ho Chi Minh", userDetails.getAddress());
    Assertions.assertEquals("peacefulman@gmail.com", userDetails.getEmail());
    Assertions.assertNotEquals("1234567", userPasswordInDb);
  }
  
  public UserDetails loadUserByUsername(String phoneNumber) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(phoneNumber)
              .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + phoneNumber));
              
    return UserDetailsImpl.build(user);
  }
  @Test
  public void loadUserByUsernameTest() {
    Throwable exception = Assertions.assertThrows(UsernameNotFoundException.class,() -> {loadUserByUsername("090949348");});
    Assertions.assertEquals("User Not Found with username: 090949348", exception.getMessage());
  }
}
