package io.jobin.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/ping")
public class PingController {

    @GetMapping("/status")
    public ResponseEntity<String> getApplicationStatus() {
        return new ResponseEntity<>("App is Running....", HttpStatus.OK);
    }

}
