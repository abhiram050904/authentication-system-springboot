package in.abhiram.authentication.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ProfileRequest {

    @NotNull(message = "Email cannot be null")
    @Email
    private String email;
    @NotBlank
    @NotNull(message = "Username cannot be null")
    private String username;
    @Size(min = 8, message = "Password must be at least 8 characters long")
    private String password;
    
}
