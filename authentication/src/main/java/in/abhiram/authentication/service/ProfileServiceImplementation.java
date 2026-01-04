package in.abhiram.authentication.service;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import in.abhiram.authentication.entity.UserEntity;
import in.abhiram.authentication.repository.UserRepository;
import in.abhiram.authentication.request.ProfileRequest;
import in.abhiram.authentication.response.ProfileResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ProfileServiceImplementation implements ProfileService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    @Override
    public ProfileResponse createProfile(ProfileRequest profileRequest){

        UserEntity userEntity = ConverttoUserEntity(profileRequest);

        if(userRepository.existsByEmail(userEntity.getEmail())){
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already in use");
        }

        userEntity=userRepository.save(userEntity);
        
        ProfileResponse profileResponse = Conv(userEntity);
        return profileResponse;

    }

    private UserEntity ConverttoUserEntity(ProfileRequest profileRequest){
       return UserEntity.builder()
        .email(profileRequest.getEmail())
        .username(profileRequest.getUsername())
        .password(passwordEncoder.encode(profileRequest.getPassword()))
        .isVerified(false)
        .verifyOtp(null)
        .verifyOtpExpireAt(0L)
        .resetPasswordOtpExpireAt(0L)
        .resetPasswordOtp(null)
        .build();
    }

    private ProfileResponse Conv(UserEntity userEntity){
        return ProfileResponse.builder()
        .id(userEntity.getId())
        .email(userEntity.getEmail())
        .username(userEntity.getUsername())
        .isVerified(userEntity.isVerified())
        .build();
    }

    @Override
    public ProfileResponse getProfile(String email) {
        UserEntity userEntity = userRepository.findByEmail(email).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found with email: " + email));
        return Conv(userEntity);
    }

}
