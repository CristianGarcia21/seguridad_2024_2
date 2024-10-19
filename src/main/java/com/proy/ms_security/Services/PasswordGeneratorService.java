package com.proy.ms_security.Services;

import org.springframework.stereotype.Service;
import java.security.SecureRandom;

@Service
public class PasswordGeneratorService {

    private static final String UPPER_CASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER_CASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL_CHARS = "!@#$%^&*()-_=+<>?";
    private static final String ALL_CHARS = UPPER_CASE + LOWER_CASE + DIGITS + SPECIAL_CHARS;
    private static final SecureRandom random = new SecureRandom();

    // Este método no necesita ninguna anotación
    public String generateRandomPassword(int length) {
        StringBuilder password = new StringBuilder(length);

        // Garantizar al menos un carácter de cada tipo
        password.append(UPPER_CASE.charAt(random.nextInt(UPPER_CASE.length())));
        password.append(LOWER_CASE.charAt(random.nextInt(LOWER_CASE.length())));
        password.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
        password.append(SPECIAL_CHARS.charAt(random.nextInt(SPECIAL_CHARS.length())));

        // Rellenar el resto de la contraseña de manera aleatoria
        for (int i = 4; i < length; i++) {
            password.append(ALL_CHARS.charAt(random.nextInt(ALL_CHARS.length())));
        }

        // Mezclar los caracteres para evitar que los primeros siempre sean UPPER, LOWER, DIGITS, SPECIAL
        return shuffleString(password.toString());
    }

    /**
     * Método para mezclar los caracteres de la contraseña
     *
     * @param input String a mezclar
     * @return String mezclado
     */
    private String shuffleString(String input) {
        StringBuilder result = new StringBuilder(input.length());
        char[] chars = input.toCharArray();

        // Barajar usando un algoritmo de Fisher-Yates
        for (int i = chars.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = chars[i];
            chars[i] = chars[j];
            chars[j] = temp;
        }

        for (char c : chars) {
            result.append(c);
        }

        return result.toString();
    }
}
