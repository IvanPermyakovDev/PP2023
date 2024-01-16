package com.example.ChatModule.security;

import com.example.ChatModule.entities.Admin;
import com.example.ChatModule.entities.Graduate;
import com.example.ChatModule.entities.Representative;
import com.example.ChatModule.entities.Role;
import com.example.ChatModule.repositories.AdminRepository;
import com.example.ChatModule.repositories.GraduateRepository;
import com.example.ChatModule.repositories.RepresentativeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {
    @Autowired
    private GraduateRepository gradRepo;
    @Autowired
    private RepresentativeRepository repRepo;
    @Autowired
    private AdminRepository adminRepo;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Override
    public UserDetails loadUserByUsername(String username){
        if(username.contains("@")){
            Graduate grad = gradRepo.findByMail(username).orElse(null);
            if(grad == null) throw new UsernameNotFoundException("User with" + username + " mail not found");

            ArrayList<Role> role = new ArrayList<Role>();
            role.add(grad.getRole());

            return new org.springframework.security.core.userdetails.User(
                    grad.getMail(),
                    grad.getPassword(),
                    role
            );
        }

        else if(username.startsWith("admin_")) {
            Admin admin = adminRepo.findByName(username).orElse(null);
            if(admin == null) throw new UsernameNotFoundException("User with" + username + " login not found");

            ArrayList<Role> role = new ArrayList<Role>();
            role.add(admin.getRole());

            return new org.springframework.security.core.userdetails.User(
                    admin.getName(),
                    admin.getPassword(),
                    role
            );
        }
        else {
            Representative rep = repRepo.findByLogin(username).orElse(null);
            if (rep == null) throw new UsernameNotFoundException("User with" + username + " login not found");

            ArrayList<Role> role = new ArrayList<Role>();
            role.add(rep.getRole());

            return new org.springframework.security.core.userdetails.User(
                    rep.getLogin(),
                    rep.getPassword(),
                    role
            );
        }
    }
}
