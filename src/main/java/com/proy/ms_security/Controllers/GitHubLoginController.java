package com.proy.ms_security.Controllers;

import com.proy.ms_security.Models.Session;
import com.proy.ms_security.Models.User;
import com.proy.ms_security.Repositories.SessionRepository;
import com.proy.ms_security.Repositories.UserRepository;
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

    @GetMapping("/login/github")  // Ruta para redirigir al login de GitHub
    public RedirectView redirectToGitHub() {
        return new RedirectView("/oauth2/authorization/github");
    }

    @GetMapping("/github/callback")  // Ruta que maneja la respuesta de GitHub
    public ResponseEntity<Map<String, Object>> handleGitHubCallback(OAuth2AuthenticationToken authentication) {
        OAuth2User oAuth2User = authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        System.out.println(email);String name = oAuth2User.getAttribute("name");
        System.out.println(name);

        oAuth2User.getAttributes().forEach((key, value) -> {
            System.out.println("Key: " + key + ", Value: " + value);
        });


        // Verifica si el usuario ya existe en la base de datos
        User user = this.userRepository.getUserByEmail(email);
        if (user == null) {
            // Si el usuario no existe, se crea uno nuevo
            user = new User();
            user.setEmail(email);
            user.setName(name); // Establece el nombre del usuario
            this.userRepository.save(user);
        }

        // Crea una nueva sesión
        Session session = new Session();
        session.setToken(UUID.randomUUID().toString());  // Genera un token aleatorio
        session.setStartAt(LocalDateTime.now());
        session.setExpiration(LocalDateTime.now().plusHours(1));  // Sesión expira en 1 hora
        session.setUsado(false);
        session.setFallido(false);
        session.setUser(user);  // Relación con el usuario
        this.sessionRepository.save(session);

        // Preparar el JSON de respuesta
        Map<String, Object> response = new HashMap<>();
        response.put("user", user);  // Información del usuario
        response.put("session", session);  // Información de la sesión

        // Devolver la respuesta en formato JSON
        return ResponseEntity.ok(response);

    }
}
