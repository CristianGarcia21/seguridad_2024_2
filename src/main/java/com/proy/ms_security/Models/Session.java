package com.proy.ms_security.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Data
@Document
public class Session {
    @Id
    private String _id;
    private Integer token2Fa;
    private Boolean usado;
    private Boolean fallido;
    private String token;
    private LocalDateTime expiration;
    private LocalDateTime startAt;
    private  LocalDateTime endAt;

    @DBRef
    private User user;

    public Session(Integer token2Fa, Boolean usado, Boolean fallido, String token, LocalDateTime expiration, LocalDateTime startAt, LocalDateTime endAt) {
        this.token2Fa = token2Fa;
        this.usado = usado;
        this.fallido = fallido;
        this.token = token;
        this.expiration = expiration;
        this.startAt = startAt;
        this.endAt = endAt;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String get_id() {
        return _id;
    }

    public void set_id(String _id) {
        this._id = _id;
    }

    public Integer getToken2Fa() {
        return token2Fa;
    }

    public void setToken2Fa(Integer token2Fa) {
        this.token2Fa = token2Fa;
    }

    public Boolean getUsado() {
        return usado;
    }

    public void setUsado(Boolean usado) {
        this.usado = usado;
    }

    public Boolean getFallido() {
        return fallido;
    }

    public void setFallido(Boolean fallido) {
        this.fallido = fallido;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public LocalDateTime getExpiration() {
        return expiration;
    }

    public void setExpiration(LocalDateTime expiration) {
        this.expiration = expiration;
    }

    public LocalDateTime getStartAt() {
        return startAt;
    }

    public void setStartAt(LocalDateTime startAt) {
        this.startAt = startAt;
    }

    public LocalDateTime getEndAt() {
        return endAt;
    }

    public void setEndAt(LocalDateTime endAt) {
        this.endAt = endAt;
    }
}
