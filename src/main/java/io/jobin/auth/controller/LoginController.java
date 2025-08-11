package io.jobin.auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/home")
    public String home(Model model, Authentication authentication) {
        String username = authentication.getName(); // Get logged-in username
        model.addAttribute("username", username);
        return "home"; // Maps to home.html
    }

}
