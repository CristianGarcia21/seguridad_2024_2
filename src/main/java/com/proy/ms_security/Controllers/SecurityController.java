package com.proy.ms_security.Controllers;

import com.proy.ms_security.Models.User;
import com.proy.ms_security.Repositories.UserRepository;
import com.proy.ms_security.Services.EncryptionService;
import com.proy.ms_security.Services.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@CrossOrigin
@RestController
@RequestMapping("/api/public/security")
public class SecurityController {
   @Autowired
   private UserRepository theUserRepository;

   @Autowired
    private EncryptionService theEncryptionService;

   @Autowired
   private JwtService theJwtServices;

   @PostMapping("/login")
    public String login(@RequestBody User theNewUser, final HttpServletResponse response)throws IOException {
       String token = "";
       User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());
       if(theActualUser != null && theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))){
         token = theJwtServices.generateToken(theActualUser);
       }else {
          response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
       }
       return token;
   }
}
