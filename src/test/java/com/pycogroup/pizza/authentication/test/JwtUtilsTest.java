package com.pycogroup.pizza.authentication.test;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;


import com.pycogroup.pizza.authentication.security.jwt.JwtUtils;
import com.pycogroup.pizza.authentication.security.service.UserDetailsServiceImpl;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@SpringBootTest
public class JwtUtilsTest {

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  UserDetailsServiceImpl userDetailsServiceImpl;

  @Autowired
  JwtUtils jwtUtils;

  @Value("${com.pizza.security.jwtSecret}")
  private String jwtSecret;

  @Value("${com.pizza.security.jwtExpirationMs}")
  private int jwtExpirationMs;

  @DisplayName("Get username from jwt token test")
  @Test
  public void getUsernameFromJwtTokenTest() {
    // given
    String jwt = Jwts.builder()
              .setSubject("username")
              .setIssuedAt(new Date())
              .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
              .signWith(SignatureAlgorithm.HS512, jwtSecret)
              .compact();
    // when
    String username = jwtUtils.getUserNameFromJwtToken(jwt);

    // then
    Assertions.assertNotNull(username);
    Assertions.assertNotNull(jwt);
    Assertions.assertEquals(username, "username");
  }

  @DisplayName("Validate jwt token test")
  @Test
  public void validateAuthenticationTokenTest() throws Exception{
    // given
    String jwt = Jwts.builder()
              .setSubject("username")
              .setIssuedAt(new Date())
              .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
              .signWith(SignatureAlgorithm.HS512, jwtSecret)
              .compact();
    String expiredJwt = Jwts.builder()
              .setSubject("username")
              .setIssuedAt(new Date())
              .setExpiration(new Date((new Date()).getTime()))
              .signWith(SignatureAlgorithm.HS512, jwtSecret)
              .compact();
    String badSignatureJwt = Jwts.builder()
              .setSubject("username")
              .setIssuedAt(new Date())
              .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
              .signWith(SignatureAlgorithm.HS512, "asdsad")
              .compact();
    String unsignedJwt = Jwts.builder()
              .setSubject("username")
              .setIssuedAt(new Date())
              .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
              .compact();
    Logger logger = (Logger) LoggerFactory.getLogger(JwtUtils.class);

    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);

    // when
    boolean empty = jwtUtils.validateJwtToken("");
    boolean valid = jwtUtils.validateJwtToken(jwt);
    boolean expired = jwtUtils.validateJwtToken(expiredJwt);
    boolean invalid = jwtUtils.validateJwtToken("asdadj");
    boolean badSignature = jwtUtils.validateJwtToken(badSignatureJwt);
    boolean unsigned = jwtUtils.validateJwtToken(unsignedJwt);
    List<ILoggingEvent> logsList = listAppender.list;

    // then
    Assertions.assertEquals("JWT claims string is empty: {}", logsList.get(0).getMessage());
    Assertions.assertEquals("JWT token is expired: {}", logsList.get(1).getMessage());
    Assertions.assertEquals("Invalid JWT token: {}", logsList.get(2).getMessage());
    Assertions.assertEquals("Invalid JWT signature: {}", logsList.get(3).getMessage());
    Assertions.assertEquals("JWT token is unsupported: {}", logsList.get(4).getMessage());
    Assertions.assertTrue(valid);
    Assertions.assertFalse(empty);
    Assertions.assertFalse(expired);
    Assertions.assertFalse(invalid);
    Assertions.assertFalse(badSignature);
    Assertions.assertFalse(unsigned);
  }
  
}
