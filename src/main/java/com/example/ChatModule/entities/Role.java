package com.example.ChatModule.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.springframework.security.core.GrantedAuthority;


@NoArgsConstructor
@Getter
public enum Role implements GrantedAuthority {
    ROLE_GRAD, ROLE_REP, ROLE_ADMIN;
    @Override
    public String getAuthority(){ return name(); }
    @Override
    public String toString(){
        return name();
    }
}