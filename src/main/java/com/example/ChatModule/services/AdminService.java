package com.example.ChatModule.services;

import com.example.ChatModule.DTOs.AdminAuthRegDTO;
import com.example.ChatModule.entities.Admin;
import com.example.ChatModule.repositories.AdminRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AdminService {
    @Autowired
    private AdminRepository repo;

    public boolean registerAdmin(@Valid AdminAuthRegDTO dto){
        Admin admin = new Admin(dto.getName(), dto.getPassword());
        admin.setRole();
        repo.save(admin);
        return namePresent(dto.getName());
    }

    private boolean namePresent(String name){
        return repo.existsByName(name);
    }
}
