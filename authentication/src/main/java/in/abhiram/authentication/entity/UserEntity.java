package in.abhiram.authentication.entity;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Document(collection = "users")
public class UserEntity {

    @Id
    private String id;
    @Indexed(unique = true)
    private String username;
    private String password;
    @Indexed(unique = true)
    @NotBlank
    private String email;
    private String verifyOtp;
    private boolean isVerified;
    private Long verifyOtpExpireAt;
    private String resetPasswordOtp;
    private Long resetPasswordOtpExpireAt;
    @CreatedDate
    private Long createdAt;
    @LastModifiedDate
    private Long updatedAt;
}
