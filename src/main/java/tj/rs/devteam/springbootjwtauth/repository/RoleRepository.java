package tj.rs.devteam.springbootjwtauth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import tj.rs.devteam.springbootjwtauth.models.ERole;
import tj.rs.devteam.springbootjwtauth.models.Role;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);
}
