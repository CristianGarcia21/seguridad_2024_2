package com.proy.ms_security.Controllers;

import com.proy.ms_security.Models.Session;
import com.proy.ms_security.Models.User;
import com.proy.ms_security.Models.VerificationRequest;
import com.proy.ms_security.Repositories.SessionRepository;
import com.proy.ms_security.Repositories.UserRepository;
import com.proy.ms_security.Services.EncryptionService;
import com.proy.ms_security.Services.JwtService;
import com.proy.ms_security.Services.NotificationService;
import com.proy.ms_security.Services.TwoFactorAuthService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.awt.print.Pageable;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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

   @Autowired
   private TwoFactorAuthService twoFactorAuthService;

   @Autowired
   private NotificationService notificationService;

   @Autowired
   private SessionRepository sessionRepository;

   @PostMapping("/login")
   public ResponseEntity<?> login(@RequestBody User theNewUser) {
      User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());

      if (theActualUser != null &&
              theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))) {

         // Generar código 2FA
         int code2fa = Integer.parseInt(this.twoFactorAuthService.generate2FACode());
         String correo = theActualUser.getEmail();
         String subject = "Codigo 2FA";
         String bodyHtml = "<html>\n" +
                 "  <body style=\"font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px;\">\n" +
                 "    <div style=\"max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.1);\">\n" +
                 "      <!-- Header -->\n" +
                 "      <h1 style=\"color: #1a73e8; text-align: center; font-size: 28px; margin-bottom: 10px;\">¡Bienvenido a JEC Logistic & Transport, <strong>"+ theActualUser.getName() + "</strong>!</h1>\n" +
                 "\n" +
                 "      <!-- Body -->\n" +
                 "      <p style=\"color: #555; font-size: 16px; text-align: center; line-height: 1.5;\">\n" +
                 "        Gracias por registrarte en <strong>JEC Logistic & Transport</strong>. Nos complace informarte que tu cuenta ha sido creada exitosamente.\n" +
                 "      </p>\n" +
                 "      <p style=\"color: #555; font-size: 16px; text-align: center;\">\n" +
                 "        A continuación, te proporcionamos tu contraseña temporal para que puedas acceder a tu cuenta:\n" +
                 "      </p>\n" +
                 "\n" +
                 "      <!-- Password Box -->\n" +
                 "      <div style=\"text-align: center; margin: 20px 0;\">\n" +
                 "        <h2 style=\"color: #34a853; font-size: 24px; background-color: #f0f4ff; padding: 10px 0; border-radius: 8px; display: inline-block; width: 100%; box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.1);\"> "+code2fa +"</h2>\n" +
                 "      </div>\n" +
                 "\n" +
                 "      <!-- Instructions -->\n" +
                 "      <p style=\"color: #555; font-size: 16px; text-align: center;\">\n" +
                 "        Te recomendamos <strong>cambiar tu contraseña</strong> tan pronto como sea posible para asegurar tu cuenta.\n" +
                 "      </p>\n" +
                 "      <p style=\"color: #555; font-size: 16px; text-align: center;\">\n" +
                 "        Si no has solicitado esta cuenta, por favor, ignora este correo.\n" +
                 "      </p>\n" +
                 "\n" +
                 "      <!-- Footer -->\n" +
                 "      <br/>\n" +
                 "      <p style=\"color: #888; font-size: 14px; text-align: center;\">\n" +
                 "        Saludos cordiales,<br/>\n" +
                 "        <strong>El equipo de soporte de JEC Logistic & Transport</strong>\n" +
                 "      </p>\n" +
                 "    </div>\n" +
                 "\n" +
                 "    <!-- Footer note -->\n" +
                 "    <div style=\"text-align: center; margin-top: 20px;\">\n" +
                 "      <p style=\"color: #999; font-size: 12px;\">© 2024 JEC Logistic & Transport. Todos los derechos reservados.</p>\n" +
                 "    </div>\n" +
                 "  </body>\n" +
                 "</html>\n";
         this.notificationService.sendEmail(subject,correo,bodyHtml);

         // Crear nueva sesión
         Session session = new Session();
         session.setToken2Fa(code2fa);
         session.setUsado(false);
         session.setFallido(false);
         session.setStartAt(LocalDateTime.now());
         session.setExpiration(LocalDateTime.now().plusMinutes(5)); // El código 2FA expira en 5 minutos
         session.setUser(theActualUser);

         sessionRepository.save(session);

         Map<String, Object> response = new HashMap<>();
         response.put("message", "Por favor verifica el código 2FA enviado");
         response.put("email", theActualUser.getEmail());
         response.put("code2fa", code2fa);

         return ResponseEntity.ok(response);
      }

      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciales inválidas");
   }

   @PostMapping("/verify-2fa")
   public ResponseEntity<?> verify2FA(@RequestBody VerificationRequest request) {
      try {
         User user = theUserRepository.getUserByEmail(request.getEmail());
         if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no encontrado");
         }

         // Usando el nuevo método más simple
         Optional<Session> sessionOpt = sessionRepository.findFirstByUserAndUsadoFalseOrderByStartAtDesc(user);

         if (sessionOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("No hay sesión pendiente de verificación");
         }

         Session session = sessionOpt.get();

         if (LocalDateTime.now().isAfter(session.getExpiration())) {
            session.setFallido(true);
            sessionRepository.save(session);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Código 2FA expirado");
         }

         if (session.getToken2Fa().equals(request.getCode2FA())) {
            String token = theJwtServices.generateToken(user);
            session.setToken(token);
            session.setUsado(true);
            session.setEndAt(LocalDateTime.now());
            sessionRepository.save(session);

            return ResponseEntity.ok(token);
         }

         session.setFallido(true);
         sessionRepository.save(session);
         return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Código 2FA inválido");
      } catch (Exception e) {
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                 .body("Error en la verificación 2FA: " + e.getMessage());
      }
   }

   @PostMapping("/logout")
   public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
      try {
         if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Token no proporcionado");
         }

         String token = authHeader.substring(7); // Remover "Bearer "

         Optional<Session> sessionOpt = sessionRepository.findByToken(token);

         if (sessionOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Sesión no encontrada");
         }

         Session session = sessionOpt.get();

         // Marcar la sesión como terminada
         session.setEndAt(LocalDateTime.now());
         session.setUsado(true);
         session.setToken(null); // Invalidar el token

         sessionRepository.save(session);

         return ResponseEntity.ok()
                 .body(new HashMap<String, String>() {{
                    put("message", "Sesión cerrada exitosamente");
                    put("logoutTime", LocalDateTime.now().toString());
                 }});

      } catch (Exception e) {
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                 .body("Error en el proceso de logout: " + e.getMessage());
      }
   }

   // Método adicional para verificar si una sesión está activa
   @GetMapping("/check-session")
   public ResponseEntity<?> checkSession(@RequestHeader("Authorization") String authHeader) {
      try {
         if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Token no proporcionado");
         }

         String token = authHeader.substring(7);
         Optional<Session> sessionOpt = sessionRepository.findByToken(token);

         if (sessionOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Sesión no encontrada");
         }

         Session session = sessionOpt.get();

         // Verificar si la sesión está activa y no ha expirado
         if (session.getEndAt() != null || LocalDateTime.now().isAfter(session.getExpiration())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Sesión expirada o cerrada");
         }

         return ResponseEntity.ok()
                 .body(new HashMap<String, Object>() {{
                    put("active", true);
                    put("expiresAt", session.getExpiration());
                    put("user", session.getUser().getEmail());
                 }});

      } catch (Exception e) {
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                 .body("Error al verificar la sesión: " + e.getMessage());
      }
   }
}
