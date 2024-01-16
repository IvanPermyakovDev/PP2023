package com.example.ChatModule.DTOs;

import com.example.ChatModule.entities.EduProgram;
import com.example.ChatModule.entities.Representative;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@NonNull
public class RepresentativeDTO {
    @NotNull
    @Min(1)
    private long id;
    @NotBlank
    private String firstname;
    @NotBlank
    private String lastname;
    private String patronimic;
    @NotNull
    @Min(1)
    private int uniId;
    @NotNull
    private List<EduProgramDTO> EPs;

    public RepresentativeDTO(Representative rep) {
        this.id = rep.getId();
        this.firstname = rep.getLastname();
        this.patronimic = rep.getPatronimic();
        this.uniId = rep.getUniversity().getId();

        var facultyEPs = rep.getEduPrograms();
        var dtos = new ArrayList<EduProgramDTO>();
        for (int i = 0; i < facultyEPs.toArray().length; i++) {
            EduProgram program = facultyEPs.get(i);
            dtos.add(new EduProgramDTO(program));

        }
        this.EPs = dtos;
    }
}
