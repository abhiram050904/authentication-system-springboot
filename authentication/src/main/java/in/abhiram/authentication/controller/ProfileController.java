package in.abhiram.authentication.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import in.abhiram.authentication.request.AuthRequest;
import in.abhiram.authentication.request.ProfileRequest;
import in.abhiram.authentication.request.ResetPasswordRequest;
import in.abhiram.authentication.request.VerifyOtpRequest;
import in.abhiram.authentication.request.VerifyResetOtpRequest;
import jakarta.validation.Valid;
import in.abhiram.authentication.response.AuthResponse;
import in.abhiram.authentication.response.ProfileResponse;
import in.abhiram.authentication.service.ProfileService;
import in.abhiram.authentication.service.CustomUserDetailsService;
import in.abhiram.authentication.service.EmailService;
import in.abhiram.authentication.utils.JwtUtil;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/profile")
@RequiredArgsConstructor
public class ProfileController {

    private final ProfileService profileService;

    private final AuthenticationManager authenticationManager;

    private final CustomUserDetailsService customUserDetailsService;

    private final JwtUtil jwtUtil;

    private final EmailService  emailService;


    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ProfileResponse register(@Valid @RequestBody ProfileRequest profileRequest){
        ProfileResponse profileResponse = profileService.createProfile(profileRequest);
        // Send OTP via email (OTP is stored in profileResponse but not serialized to JSON)
        String otp = profileResponse.getOtp();
        emailService.sendEmail(profileResponse.getEmail(), "Verify Your Account", 
            "<h1>Welcome, " + profileResponse.getUsername() + "!</h1>" +
            "<p>Thank you for registering. Please verify your account using the OTP below:</p>" +
            "<h2 style='color: #4CAF50; font-size: 32px; letter-spacing: 5px;'>" + otp + "</h2>" +
            "<p>Your OTP will expire in 15 minutes.</p>");
        return profileResponse;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest){
        try{
            System.out.println("Attempting login for: " + authRequest.getEmail());
            
            // Check if user is verified before authentication
            ProfileResponse profile = profileService.getProfile(authRequest.getEmail());
            if (!profile.isVerified()) {
                Map<String, Object> response = new HashMap<>();
                response.put("error", true);
                response.put("message", "Please verify your account with OTP before logging in");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
            }
            
            authenticate(authRequest.getEmail(), authRequest.getPassword());
            System.out.println("Authentication successful");
            final UserDetails userDetails= customUserDetailsService.loadUserByUsername(authRequest.getEmail());
            final String jwtToken = jwtUtil.generateToken(userDetails);
            ResponseCookie responseCookie=ResponseCookie.from("jwtToken", jwtToken)
                .httpOnly(true)
                .path("/")
                .maxAge(7 * 24 * 60 * 60)
                .sameSite("Strict")
                .build();

            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE,responseCookie.toString())
                .body(new AuthResponse(authRequest.getEmail(), jwtToken));
        }
        catch(BadCredentialsException e){
           System.out.println("BadCredentialsException: " + e.getMessage());
           Map<String,Object> response = new HashMap<>();
           response.put("error", true);
           response.put("message", "Invalid Credentials");
           return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        catch(DisabledException e){
            System.out.println("DisabledException: " + e.getMessage());
            Map<String,Object> response = new HashMap<>();
            response.put("error", true);
            response.put("message", "User Disabled");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        catch(Exception e){
            System.out.println("General Exception: " + e.getClass().getName() + " - " + e.getMessage());
            e.printStackTrace();
            Map<String,Object> response = new HashMap<>();
            response.put("error", true);
            response.put("message", "Authentication Failed");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    private void authenticate(String email, String password) throws Exception {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
    }

    @GetMapping("/test")
    public String test(){
        return "Profile Service is up and running!";
    }

    @GetMapping("/get-profile")
    public ProfileResponse getProfile(@CurrentSecurityContext(expression = "authentication.name") String email){
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);
        ProfileResponse profileResponse = profileService.getProfile(userDetails.getUsername());
        return profileResponse;
    }


    @GetMapping("/is-authenticated")
    public ResponseEntity<Boolean> isAEntityuthenticated(@CurrentSecurityContext(expression = "authentication.name") String email){
        boolean isAuthenticated = (email != null && !email.isEmpty());
        return ResponseEntity.ok(isAuthenticated);
    }
    
    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@Valid @RequestBody VerifyOtpRequest verifyOtpRequest){
        try {
            ProfileResponse profileResponse = profileService.verifyOtp(verifyOtpRequest);
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Account verified successfully");
            response.put("user", profileResponse);
            return ResponseEntity.ok(response);
        } catch (ResponseStatusException e) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", true);
            response.put("message", e.getReason());
            return ResponseEntity.status(e.getStatusCode()).body(response);
        }
    }
    
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request){
        try {
            String email = request.get("email");
            if (email == null || email.isEmpty()) {
                Map<String, Object> response = new HashMap<>();
                response.put("error", true);
                response.put("message", "Email is required");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
            }
            
            String message = profileService.sendResetPasswordOtp(email);
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", message);
            return ResponseEntity.ok(response);
        } catch (ResponseStatusException e) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", true);
            response.put("message", e.getReason());
            return ResponseEntity.status(e.getStatusCode()).body(response);
        }
    }
    
    @PostMapping("/verify-reset-otp")
    public ResponseEntity<?> verifyResetOtp(@Valid @RequestBody VerifyResetOtpRequest verifyResetOtpRequest){
        try {
            String message = profileService.verifyResetOtp(verifyResetOtpRequest);
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", message);
            return ResponseEntity.ok(response);
        } catch (ResponseStatusException e) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", true);
            response.put("message", e.getReason());
            return ResponseEntity.status(e.getStatusCode()).body(response);
        }
    }
    
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest){
        try {
            String message = profileService.resetPassword(resetPasswordRequest);
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", message);
            return ResponseEntity.ok(response);
        } catch (ResponseStatusException e) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", true);
            response.put("message", e.getReason());
            return ResponseEntity.status(e.getStatusCode()).body(response);
        }
    }
    
}
