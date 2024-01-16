package com.example.ChatModule.controllers;

import com.example.ChatModule.DTOs.DocumentDTO;
import com.example.ChatModule.services.DocumentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.view.RedirectView;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/doc")
public class DocumentController {
    @Autowired
    private DocumentService service;

    private static final Logger logger = LoggerFactory.getLogger(DocumentController.class);

    @GetMapping(value = "/{docId}",produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> getFileById(@PathVariable long docId){
        DocumentDTO doc = service.getDocument(docId);

        if (doc==null) return new ResponseEntity<>(HttpStatus.NOT_FOUND);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentDisposition(ContentDisposition.builder("inline").filename(doc.getName()).build());
        return ResponseEntity.ok().headers(headers).body(doc.getContent());
    }
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<HttpStatus> addFile(@RequestPart("content")MultipartFile file,
                                @RequestParam("graduateId") long graduateId){
        try {
            String name = file.getOriginalFilename();
            byte[] content = file.getBytes();
            DocumentDTO dto = new DocumentDTO(content,name,graduateId);
            service.createDocument(dto);
            logger.info("Абитуриент {} добавил документ: {}.", graduateId, name);
            return new ResponseEntity<>(HttpStatus.CREATED);
        }
        catch (IOException e){
            logger.error("Ошибка добавления документа абитуриентом {}.", graduateId);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/{docId}")
    public ResponseEntity<HttpStatus> removeFile(@PathVariable long docId){
        if(service.deleteDocument(docId)){
            logger.info("Удалён документ {}.", docId);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        logger.error("Ошибка удаления документа {}.", docId);
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
}
