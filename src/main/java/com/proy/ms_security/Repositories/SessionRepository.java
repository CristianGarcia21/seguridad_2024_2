package com.proy.ms_security.Repositories;


import com.proy.ms_security.Models.Session;
import com.proy.ms_security.Models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.awt.print.Pageable;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface SessionRepository extends MongoRepository<Session, String> {
    @Query("{'user.$id': ObjectId(?0)}")
    public List<Session> getSessionByUser(String userId);

    // Buscar sesión por token
    Optional<Session> findByToken(String token);

    // Buscar la última sesión no usada de un usuario específico
    // Metodo más simple y seguro
    Optional<Session> findFirstByUserAndUsadoFalseOrderByStartAtDesc(User user);

    // Buscar sesiones activas (no expiradas y no usadas)
    @Query("{'user': ?0, 'usado': false, 'expiration': {$gt: ?1}}")
    List<Session> findActiveSessions(User user, LocalDateTime currentTime);
}
