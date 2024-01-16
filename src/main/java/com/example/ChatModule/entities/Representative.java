package com.example.ChatModule.entities;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "Representatives")
@NonNull
@AllArgsConstructor
@NoArgsConstructor
@Getter
public class Representative {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rep_id")
    private long id;
    @Setter
    @Column(name = "rep_login")
    private String login;
    @Column(name = "rep_pw")
    private String password;
    @Setter
    @Column(name = "fname")
    private String firstname;
    @Setter
    @Column(name = "lname")
    private String lastname;
    @Setter
    @Column(name = "patronimic")
    private String patronimic;
    @Setter
    @ManyToOne(optional = false)
    @JoinColumn(name = "uni_id")
    private University university;
    @ManyToMany
    @JoinTable(name="RepresentativeEP",joinColumns = @JoinColumn(name="rep_id"),inverseJoinColumns = @JoinColumn(name="ep_id"))
    private List<EduProgram> eduPrograms;
    @Column(name="salt")
    private String salt;
    @Enumerated
    private Role role;

    private void generateSalt(){
        if (this.salt==null)
            this.salt= BCrypt.gensalt();
    }
    public void setPassword(String password) {
        generateSalt();
        password=BCrypt.hashpw(password,salt);
        this.password=password;
    }

    public void setRole() {
        this.role = Role.ROLE_REP;
    }

    public void addEP(EduProgram ep){
        if (!eduPrograms.contains(ep)) eduPrograms.add(ep);
    }

    public void removeEP(EduProgram ep){
        eduPrograms.remove(ep);
    }
}
