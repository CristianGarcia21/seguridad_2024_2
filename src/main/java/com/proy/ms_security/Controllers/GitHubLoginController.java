package com.proy.ms_security.Controllers;

import com.proy.ms_security.Models.Session;
import com.proy.ms_security.Models.User;
import com.proy.ms_security.Repositories.SessionRepository;
import com.proy.ms_security.Repositories.UserRepository;
import com.proy.ms_security.Services.EncryptionService;
import com.proy.ms_security.Services.JwtService;
import com.proy.ms_security.Services.NotificationService;
import com.proy.ms_security.Services.PasswordGeneratorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
public class GitHubLoginController {

    private static final Logger log = LoggerFactory.getLogger(GitHubLoginController.class);
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private PasswordGeneratorService passwordGeneratorService;

    @Autowired
    private EncryptionService encryptionService;

    @Autowired
    private NotificationService notificationService;

    @GetMapping("/login/github")
    public RedirectView redirectToGitHub() {
        return new RedirectView("/oauth2/authorization/github");
    }

    @GetMapping("/github/callback")
    public ResponseEntity<Map<String, Object>> handleGitHubCallback(OAuth2AuthenticationToken authentication) {
        OAuth2User oAuth2User = authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");


        /**   Ver la informacion que devuelve el login con GitHub
        oAuth2User.getAttributes().forEach((key, value) -> {
            System.out.println("Key: " + key + ", Value: " + value);
        });
         */


        User user = this.userRepository.getUserByEmail(email);
        if (user == null) {

            user = new User();
            user.setEmail(email);
            user.setName(name);
            String password = passwordGeneratorService.generateRandomPassword(12);
            // Enviar correo con la contraseña generada
            String subject = "Asignacion de contraseña";
            String bodyHtml = "<html>\n" +
                    "  <body style=\"font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px;\">\n" +
                    "    <div style=\"max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.1);\">\n" +
                    "      <!-- Header -->\n" +
                    "      <h1 style=\"color: #1a73e8; text-align: center; font-size: 28px; margin-bottom: 10px;\">¡Bienvenido a JEC Logistic & Transport, <strong>"+ name + "</strong>!</h1>\n" +
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
                    "        <h2 style=\"color: #34a853; font-size: 24px; background-color: #f0f4ff; padding: 10px 0; border-radius: 8px; display: inline-block; width: 100%; box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.1);\"> "+password +"</h2>\n" +
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

            notificationService.sendEmail(subject,email,bodyHtml);
            String encriptada = encryptionService.convertSHA256(password);
            user.setPassword(encriptada);
            this.userRepository.save(user);
        }
        //Crea el token con el usaurio
        String tokenJWT = jwtService.generateToken(user);

        // Crea una nueva sesión
        Session session = new Session();
        session.setToken(tokenJWT);
        session.setStartAt(LocalDateTime.now());
        session.setExpiration(LocalDateTime.now().plusHours(1));
        session.setUsado(false);
        session.setFallido(false);
        session.setUser(user);
        this.sessionRepository.save(session);

        // Preparar el JSON de respuesta
        Map<String, Object> response = new HashMap<>();
        response.put("user", user);
        response.put("session", session);


        // Devolver la respuesta en formato JSON
        return ResponseEntity.ok(response);

    }
}
