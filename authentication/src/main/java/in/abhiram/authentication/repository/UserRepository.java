package in.abhiram.authentication.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import in.abhiram.authentication.entity.UserEntity;

public interface UserRepository extends MongoRepository<UserEntity,String> {
    Optional<UserEntity> findByUsername(String username);
    Optional<UserEntity> findByEmail(String email);   

    Boolean existsByEmail(String email);
}
