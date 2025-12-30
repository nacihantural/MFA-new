package com.nacihan.mfa.MFA_Authenticator.repository;

import com.nacihan.mfa.MFA_Authenticator.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository

public interface UserRepository extends JpaRepository<User,Long> {

    User findByUsername(String username);

}
