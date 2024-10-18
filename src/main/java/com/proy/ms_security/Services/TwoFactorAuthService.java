package com.proy.ms_security.Services;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;

@Service
public class TwoFactorAuthService {

    private static final int CODE_LENGTH = 6;
    private static final SecureRandom random = new SecureRandom();

    public String generate2FACode() {
        int code = random.nextInt((int) Math.pow(10, CODE_LENGTH));
        return String.format("%06d", code);
    }
}
