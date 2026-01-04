package in.abhiram.authentication.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface UserDetailsService extends org.springframework.security.core.userdetails.UserDetailsService {

    @Override
    UserDetails loadUserByUsername(String email);
    
}
