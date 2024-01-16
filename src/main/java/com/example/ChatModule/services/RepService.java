package com.example.ChatModule.services;

import com.example.ChatModule.DTOs.RepresentativeAuthDTO;
import com.example.ChatModule.DTOs.RepresentativeRegistrationDTO;
import com.example.ChatModule.entities.Faculty;
import com.example.ChatModule.entities.Representative;
import com.example.ChatModule.repositories.EduProgramRepository;
import com.example.ChatModule.repositories.RepresentativeRepository;
import com.example.ChatModule.repositories.UniversityRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;


@Service
public class RepService {
    @Autowired
    private RepresentativeRepository repo;
    @Autowired
    private UniversityRepository uniRepo;
    @Autowired
    private EduProgramRepository epRepo;


    public boolean registerRep(@Valid RepresentativeRegistrationDTO dto){
        var uniOpt = uniRepo.findByName(dto.getUniName());
        if (uniOpt.isEmpty()||loginPresent(dto.getLogin())) return false;
        var rep = new Representative();
        rep.setLogin(dto.getLogin());
        rep.setFirstname(dto.getFirstname());
        rep.setLastname(dto.getLastname());
        rep.setPatronimic(dto.getPatronimic());
        rep.setPassword(dto.getPassword());
        rep.setUniversity(uniOpt.get());
        rep.setRole();
        repo.save(rep);
        return loginPresent(dto.getLogin());
    }

    @PreAuthorize("hasRole('ADMIN')")
    public boolean killRep(int repId){
        boolean exists = repo.existsById(repId);
        repo.deleteById(repId);
        return exists;
    }

    private boolean loginPresent(String login){
        Representative rep = repo.findByLogin(login).orElse(null);
        return rep!=null;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public boolean addEP(String repLogin, String EPId) {

        Representative rep = repo.findByLogin(repLogin).orElse(null);
        if (rep==null) return false;
        var epOpt = epRepo.findById(EPId);
        if (epOpt.isEmpty()) return false;
        rep.addEP(epOpt.get());
        repo.save(rep);
        return true;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public boolean removeEP(String repLogin, String EPId){
        Representative rep = repo.findByLogin(repLogin).orElse(null);
        if (rep==null) return false;
        var epOpt = epRepo.findById(EPId);
        if (epOpt.isEmpty()) return false;
        rep.removeEP(epOpt.get());
        repo.save(rep);
        return true;
    }

}
