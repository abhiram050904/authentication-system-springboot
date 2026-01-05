package in.abhiram.authentication.response;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ProfileResponse {

    private String id;
    private String username;
    private String email;
    private boolean isVerified;
    
    @JsonIgnore // Don't serialize OTP in JSON responses
    private String otp;
}
