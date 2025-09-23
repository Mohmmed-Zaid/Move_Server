package com.moveapp.movebackend.repository;

import com.moveapp.movebackend.model.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Find a user by their email address
    Optional<User> findByEmail(String email);

    // Check if a user with the given email exists
    Boolean existsByEmail(String email);

    // Find a user by provider-specific ID and authentication provider (e.g., Google, Apple, Local)
    Optional<User> findByProviderIdAndAuthProvider(String providerId, String authProvider);
}
