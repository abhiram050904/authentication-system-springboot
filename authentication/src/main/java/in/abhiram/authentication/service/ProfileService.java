package in.abhiram.authentication.service;

import in.abhiram.authentication.request.ProfileRequest;
import in.abhiram.authentication.request.ResetPasswordRequest;
import in.abhiram.authentication.request.VerifyOtpRequest;
import in.abhiram.authentication.request.VerifyResetOtpRequest;
import in.abhiram.authentication.response.ProfileResponse;

public interface ProfileService {
    ProfileResponse createProfile(ProfileRequest profileRequest);

    ProfileResponse getProfile(String email);
    
    ProfileResponse verifyOtp(VerifyOtpRequest verifyOtpRequest);

    String sendResetPasswordOtp(String email);
    
    String verifyResetOtp(VerifyResetOtpRequest verifyResetOtpRequest);
    
    String resetPassword(ResetPasswordRequest resetPasswordRequest);
}
