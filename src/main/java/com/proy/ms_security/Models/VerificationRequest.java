package com.proy.ms_security.Models;

import lombok.Data;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class VerificationRequest {
    private String email;
    private int code2FA;

    public VerificationRequest(String email, int code2FA) {
        this.email = email;
        this.code2FA = code2FA;
    }

    // Getters y setters
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public int getCode2FA() {
        return code2FA;
    }

    public void setCode2FA(int code2FA) {
        this.code2FA = code2FA;
    }
}