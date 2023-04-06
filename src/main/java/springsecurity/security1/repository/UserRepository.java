package springsecurity.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import springsecurity.security1.domain.User;

public interface UserRepository extends JpaRepository<User, Integer> {
     User findByUsername(String username);

}
