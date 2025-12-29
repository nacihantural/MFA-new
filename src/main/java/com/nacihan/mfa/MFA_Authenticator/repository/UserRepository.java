package com.nacihan.mfa.MFA_Authenticator.repository;

import com.nacihan.mfa.MFA_Authenticator.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository

public interface UserRepository extends JpaRepository<User,Long> {

    /**
     * Spring Data JPA bu metodun adını okur ve otomatik olarak
     * "SELECT * FROM APP_USER WHERE username = ?" sorgusunu oluşturur.
     * Bu işleme "Query Method" (Sorgu Metodu) denir.
     */

    User findByUsername(String username);

}
