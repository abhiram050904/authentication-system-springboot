package in.abhiram.authentication.service;

import in.abhiram.authentication.request.ProfileRequest;
import in.abhiram.authentication.response.ProfileResponse;

public interface ProfileService {
    ProfileResponse createProfile(ProfileRequest profileRequest);

    ProfileResponse getProfile(String email);
}
