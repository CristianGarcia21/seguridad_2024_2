package com.proy.ms_security.Repositories;

import com.proy.ms_security.Models.CrediCards;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;

public interface CreditCardRepository extends MongoRepository<CrediCards, String> {
    @Query("{'user.$id': ObjectId(?0)}")
    public List<CrediCards> getCardByUser(String userId);
}
