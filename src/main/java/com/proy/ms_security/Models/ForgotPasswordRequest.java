package com.proy.ms_security.Models;

import lombok.Data;

@Data
public class ForgotPasswordRequest {
    private String email;

    public String getEmail() {
        return email;
    }


}
