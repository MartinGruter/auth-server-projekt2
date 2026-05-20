package se.iths.martin.authserverprojekt2.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import se.iths.martin.authserverprojekt2.model.AppUser;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);
}
