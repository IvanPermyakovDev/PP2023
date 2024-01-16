package com.example.ChatModule.controllers;

import com.example.ChatModule.DTOs.EduProgramDTO;
import com.example.ChatModule.DTOs.RepresentativeAuthDTO;
import com.example.ChatModule.DTOs.RepresentativeRegistrationDTO;
import com.example.ChatModule.services.RepService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/rep")
public class RepresentativeController {
    @Autowired
    private RepService service;
    private static final Logger logger = LoggerFactory.getLogger(RepresentativeController.class);

    @GetMapping("/hello")
    @PreAuthorize("hasRole('REP')")
    public String hello(){
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }

    @PostMapping("/register")
    public ResponseEntity<HttpStatus> RegisterRep(@Valid @RequestBody RepresentativeRegistrationDTO dto){
        if (service.registerRep(dto)) {
            return new ResponseEntity<>(HttpStatus.CREATED);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/{repLogin}/programs")
    public ResponseEntity<HttpStatus> addEP(@PathVariable String repLogin, @Valid @RequestBody EduProgramDTO dto){
        if(service.addEP(repLogin,dto.getId())){
            logger.info("Представитель {} теперь консультирует по образовательной программе {}.", repLogin,dto.getId());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        logger.error("Ошибка добавления ОП представителю {}.", repLogin);
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @DeleteMapping("/{repLogin}/programs/{programId}")
    public ResponseEntity<HttpStatus> removeEP(@PathVariable String repLogin, @PathVariable String programId){
        if(service.removeEP(repLogin,programId)) {
            logger.info("Представитель {} больше не консультирует по образовательной программе {}.", repLogin,programId);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        logger.error("Ошибка снятия ОП у представителя {}.", repLogin);
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
    @DeleteMapping("/{repId}")
    public ResponseEntity<HttpStatus> killRep(@PathVariable int repId){
        if(service.killRep(repId)) {
            logger.info("Удалён представитель {}.", repId);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        logger.error("Ошибка удаления представителя {}.", repId);
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
}
