package com.example.ChatModule.services;

import com.example.ChatModule.DTOs.GraduateAuthDTO;
import com.example.ChatModule.DTOs.GraduateDTO;
import com.example.ChatModule.DTOs.GraduateRegistrationDTO;
import com.example.ChatModule.entities.Graduate;
import com.example.ChatModule.repositories.GraduateRepository;
import jakarta.annotation.security.RolesAllowed;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Service
public class GraduateService {
    @Autowired
    private GraduateRepository repo;

    public boolean registerGraduate(@Valid GraduateRegistrationDTO dto){
        boolean mailPresent = mailPresent(dto.getMail());
        if (mailPresent) return false;
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        var grad = new Graduate();
        grad.setMail(dto.getMail());
        grad.setPassword(dto.getPassword());
        grad.setFirstname(dto.getFirstname());
        grad.setLastname(dto.getLastname());
        grad.setPatronimic(dto.getPatronimic());
        grad.setDateOfBirth(LocalDate.parse(dto.getDateOfBirth(),formatter));
        grad.setGradFrom(dto.getGradFrom());
        grad.setRegion(dto.getRegion());
        grad.setRole();
        repo.save(grad);
        return mailPresent(dto.getMail());
    }

    private boolean mailPresent(String mail){
        return repo.existsByMail(mail);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public boolean killGrad(long id){
        boolean exists = repo.existsById(id);
        repo.deleteById(id);
        return exists;
    }

    @PreAuthorize("hasRole('GRAD')")
    public boolean uploadImage(long gradId, byte[] image){
        Graduate graduate = repo.findById(gradId).orElse(null);
        if (graduate==null) return false;
        graduate.setPhoto(image);
        repo.save(graduate);
        return true;
    }


    @PreAuthorize("hasAnyRole('GRAD', 'ADMIN')")
    public boolean deleteImage(long gradId){
        Graduate grad = repo.findById(gradId).orElse(null);
        if (grad==null) return false;
        if (grad.getPhoto()==null||grad.getPhoto().length<=1) return false;
        grad.setPhoto(null);
        repo.save(grad);
        return true;
    }

    public byte[] getGradImage(long gradId){
        Graduate grad = repo.findById(gradId).orElse(null);
        if (grad==null) return null;
        return grad.getPhoto();
    }

    public GraduateDTO getGradDtoByMail(String mail){
        Graduate grad = repo.findByMail(mail).orElse(null);
        if(grad == null) return null;
        return new GraduateDTO(grad);
    }
}
