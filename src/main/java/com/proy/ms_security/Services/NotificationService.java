package com.proy.ms_security.Services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class NotificationService {

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${notification.service.url}")
    private String emailServiceUrl;

    public void sendEmail(String subject, String recipient, String bodyHtml) {

        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("subject", subject);
        requestBody.put("recipient", recipient);
        requestBody.put("body_html", bodyHtml);


        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);


        HttpEntity<Map<String, String>> request = new HttpEntity<>(requestBody, headers);


        ResponseEntity<String> response = restTemplate.exchange(emailServiceUrl, HttpMethod.POST, request, String.class);


        if (response.getStatusCode().is2xxSuccessful()) {
            System.out.println("Correo enviado exitosamente.");
        } else {
            System.out.println("Error al enviar el correo: " + response.getStatusCode());
        }
    }
}

