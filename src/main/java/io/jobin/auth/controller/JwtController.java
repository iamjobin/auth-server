package io.jobin.auth.controller;

import io.jobin.auth.dto.JwtResponse;
import io.jobin.auth.dto.LoginRequest;
import io.jobin.auth.jwt.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/jwt")
public class JwtController {

    private final JwtUtil jwtUtil;

    private final AuthenticationManager authenticationManager;

    public JwtController(
            JwtUtil jwtUtil,
            AuthenticationManager authenticationManager
    ) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping(path = "/generate/token")
    public ResponseEntity<JwtResponse> createToken(
            @RequestBody LoginRequest loginRequest
    ) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUserName(), loginRequest.getPassword())
        );
        String token = jwtUtil.generateToken(authentication);
        return new ResponseEntity<>(new JwtResponse(token), HttpStatus.OK);
    }

}
