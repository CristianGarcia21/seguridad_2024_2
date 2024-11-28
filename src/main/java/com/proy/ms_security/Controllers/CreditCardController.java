package com.proy.ms_security.Controllers;

import com.proy.ms_security.Models.CrediCards;
import com.proy.ms_security.Models.Profile;
import com.proy.ms_security.Models.User;
import com.proy.ms_security.Repositories.CreditCardRepository;
import com.proy.ms_security.Repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/creditcard")
public class CreditCardController {
    @Autowired
    private CreditCardRepository creditCardRepository;

    @Autowired
    private UserRepository theUserRepository;

    // Obtener todas las tarjetas
    @GetMapping
    public List<CrediCards> getAllCreditCards() {
        return creditCardRepository.findAll();
    }

    // Obtener una tarjeta por ID
    @GetMapping("/{id}")
    public CrediCards findById (@PathVariable String id) {
        CrediCards theCreditCard = creditCardRepository.findById(id).orElse(null);
        return  theCreditCard;
    }

    // Crear una nueva tarjeta
    @PostMapping
    public CrediCards createCreditCard(@RequestBody CrediCards newCrediCard) {
        return creditCardRepository.save(newCrediCard);
    }

    // Actualizar una tarjeta existente
    @PutMapping("/{id}")
    public CrediCards update(@PathVariable String id, @RequestBody CrediCards newCard) {
       CrediCards actualCard = this.creditCardRepository.findById(id).orElse(null);
       if(actualCard != null){
           actualCard.setNumeroTarjeta(newCard.getNumeroTarjeta());
           actualCard.setFechaExpiracion(newCard.getFechaExpiracion());
           this.creditCardRepository.save(actualCard);
           return actualCard;
       }else {
           return  null;
       }
    }

    // Eliminar una tarjeta por ID
    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        CrediCards theCard = this.creditCardRepository.findById(id).orElse(null);
        if (theCard != null){
            this.creditCardRepository.delete(theCard);
        }
    }

    //Match Tarjeta con usuario
    @PostMapping("{cardId}/user/{userId}")
    public CrediCards matchUser(@PathVariable String cardId, @PathVariable String userId ) {
        CrediCards theCard = this.creditCardRepository.findById(cardId).orElse(null);
        User theUser = this.theUserRepository.findById(userId).orElse(null);
        if (theCard != null && theUser != null){
            theCard.setUser(theUser);
            this.creditCardRepository.save(theCard);
            return theCard;
        }else {
            return null;
        }
    }

    //Obtener tarjetas por Usuaio
    @GetMapping("user/{userId}")
    public List<CrediCards> getSessionsByUser (@PathVariable String userId){
        return this.creditCardRepository.getCardByUser(userId);
    }

}
