package com.example.ChatModule.controllers;

import com.example.ChatModule.DTOs.*;
import com.example.ChatModule.security.JwtService;
import com.example.ChatModule.security.AuthService;
import com.example.ChatModule.security.LogoutService;
import com.example.ChatModule.services.AdminService;
import com.example.ChatModule.services.GraduateService;
import com.example.ChatModule.services.RepService;
import jakarta.validation.Valid;
//import lombok.var;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import java.io.IOException;
import java.nio.file.Files;
import java.security.Principal;

@RestController
public class AuthController {
    @Autowired
    private GraduateService gradService;
    @Autowired
    private RepService repService;
    @Autowired
    private AdminService adminService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthService authService;
    @Autowired
    private LogoutService logoutService;

    @PostMapping("/register/grad")
    public ResponseEntity<HttpStatus> registerGrad(@Valid @RequestBody GraduateRegistrationDTO dto){
        if (gradService.registerGraduate(dto)){
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/register/rep")
    public ResponseEntity<HttpStatus> RegisterRep(@Valid @RequestBody RepresentativeRegistrationDTO dto){
        if (repService.registerRep(dto)) {
            return new ResponseEntity<>(HttpStatus.CREATED);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/register/admin")
    public ResponseEntity<HttpStatus> RegisterAdmin(@Valid @RequestBody AdminAuthRegDTO dto){
        if (adminService.registerAdmin(dto)) {
            return new ResponseEntity<>(HttpStatus.CREATED);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/auth/rep")
    public ResponseEntity<?> createRepAuthToken(@RequestBody RepresentativeAuthDTO dto) {
        return authService.createRepAuthToken(dto);
    }

    @PostMapping("/login")
    public String createGradAuthToken(@RequestParam String username, @RequestParam String password) {
//        ResponseEntity<JwtResponse> token = authService.createGradAuthToken(dto);
//        RedirectView redirectView = new RedirectView();
//        redirectView.setUrl("/grad_lk");
//        return redirectView;
        authService.createGradAuthToken(new GraduateAuthDTO(username, password));
        return "/grad_lk";
    }

    @PostMapping("/auth/admin")
    public ResponseEntity<?> createAdminAuthToken(@RequestBody AdminAuthRegDTO dto) {
        return authService.createAdminAuthToken(dto);
    }

    @GetMapping("/admin/hello")
    @PreAuthorize("hasRole('ADMIN')")
    public String hello(){
        return "<h1>hello, admin!</h1>";
    }

    /**
     * <p>geting username from security context</p>
     *
     * @return username
     */
    @GetMapping("/context")
    public String getContext(){
        return String.format(SecurityContextHolder.getContext().getAuthentication().getName());
    }
}
