package in.abhiram.authentication.service;

import java.security.SecureRandom;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import in.abhiram.authentication.entity.UserEntity;
import in.abhiram.authentication.repository.UserRepository;
import in.abhiram.authentication.request.ProfileRequest;
import in.abhiram.authentication.request.ResetPasswordRequest;
import in.abhiram.authentication.request.VerifyOtpRequest;
import in.abhiram.authentication.request.VerifyResetOtpRequest;
import in.abhiram.authentication.response.ProfileResponse;
import jakarta.validation.OverridesAttribute;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ProfileServiceImplementation implements ProfileService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;
    
    private final EmailService emailService;

    @Override
    public ProfileResponse createProfile(ProfileRequest profileRequest){

        UserEntity userEntity = ConverttoUserEntity(profileRequest);

        if(userRepository.existsByEmail(userEntity.getEmail())){
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already in use");
        }

        // Store OTP before saving
        String otp = userEntity.getVerifyOtp();
        
        userEntity=userRepository.save(userEntity);
        
        ProfileResponse profileResponse = Conv(userEntity);
        // Temporarily store OTP in response to send via email (not exposed to client)
        profileResponse.setOtp(otp);
        return profileResponse;

    }

    private UserEntity ConverttoUserEntity(ProfileRequest profileRequest){
       String otp = generateOtp();
       Long otpExpiry = System.currentTimeMillis() + (15 * 60 * 1000); // 15 minutes
       
       return UserEntity.builder()
        .email(profileRequest.getEmail())
        .username(profileRequest.getUsername())
        .password(passwordEncoder.encode(profileRequest.getPassword()))
        .isVerified(false)
        .verifyOtp(otp)
        .verifyOtpExpireAt(otpExpiry)
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

    @Override
    public ProfileResponse verifyOtp(VerifyOtpRequest verifyOtpRequest) {
        UserEntity userEntity = userRepository.findByEmail(verifyOtpRequest.getEmail())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found with email: " + verifyOtpRequest.getEmail()));
        
        if (userEntity.isVerified()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User is already verified");
        }
        
        if (userEntity.getVerifyOtp() == null || userEntity.getVerifyOtp().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No OTP found for this user");
        }
        
        if (System.currentTimeMillis() > userEntity.getVerifyOtpExpireAt()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "OTP has expired");
        }
        
        if (!userEntity.getVerifyOtp().equals(verifyOtpRequest.getOtp())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid OTP");
        }
        
        // Mark user as verified and clear OTP
        userEntity.setVerified(true);
        userEntity.setVerifyOtp(null);
        userEntity.setVerifyOtpExpireAt(0L);
        userEntity = userRepository.save(userEntity);
        
        return Conv(userEntity);
    }
    
    private String generateOtp() {
        SecureRandom random = new SecureRandom();
        int otpNumber = 100000 + random.nextInt(900000); // 6-digit OTP
        return String.valueOf(otpNumber);
    }


    @Override
    public String sendResetPasswordOtp(String email) {
        UserEntity userEntity = userRepository.findByEmail(email)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found with email: " + email));

        // Generate new reset password OTP
        String resetOtp = generateOtp();
        Long otpExpiry = System.currentTimeMillis() + (15 * 60 * 1000); // 15 minutes
        
        // Send OTP via email
        emailService.sendEmail(email, "Reset Your Password", 
            "<h1>Password Reset Request</h1>" +
            "<p>You have requested to reset your password. Please use the OTP below:</p>" +
            "<h2 style='color: #FF5722; font-size: 32px; letter-spacing: 5px;'>" + resetOtp + "</h2>" +
            "<p>Your OTP will expire in 15 minutes.</p>" +
            "<p>If you did not request this, please ignore this email.</p>");
        
        // Update user with reset password OTP
        userEntity.setResetPasswordOtp(resetOtp);
        userEntity.setResetPasswordOtpExpireAt(otpExpiry);
        userRepository.save(userEntity);
        
        return "Password reset OTP sent successfully to your email";
    }

    @Override
    public String verifyResetOtp(VerifyResetOtpRequest verifyResetOtpRequest) {
        // Find user by email
        UserEntity userEntity = userRepository.findByEmail(verifyResetOtpRequest.getEmail())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found with email: " + verifyResetOtpRequest.getEmail()));
        
        // Verify reset OTP exists
        if (userEntity.getResetPasswordOtp() == null || userEntity.getResetPasswordOtp().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No password reset OTP found. Please request a new one");
        }
        
        // Check if OTP has expired
        if (System.currentTimeMillis() > userEntity.getResetPasswordOtpExpireAt()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password reset OTP has expired. Please request a new one");
        }
        
        // Verify OTP matches
        if (!userEntity.getResetPasswordOtp().equals(verifyResetOtpRequest.getOtp())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid OTP");
        }
        
        return "OTP verified successfully. You can now reset your password";
    }

    @Override
    public String resetPassword(ResetPasswordRequest resetPasswordRequest) {
        // Validate passwords match
        if (!resetPasswordRequest.getPassword().equals(resetPasswordRequest.getConfirmPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password and confirm password do not match");
        }
        
        // Find user by email
        UserEntity userEntity = userRepository.findByEmail(resetPasswordRequest.getEmail())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found with email: " + resetPasswordRequest.getEmail()));
        
        // Update password and clear reset OTP
        userEntity.setPassword(passwordEncoder.encode(resetPasswordRequest.getPassword()));
        userEntity.setResetPasswordOtp(null);
        userEntity.setResetPasswordOtpExpireAt(0L);
        userRepository.save(userEntity);
        
        return "Password reset successfully. You can now login with your new password";
    }
}
