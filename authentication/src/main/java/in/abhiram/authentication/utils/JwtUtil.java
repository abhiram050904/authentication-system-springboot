package in.abhiram.authentication.utils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;


@Component
public class JwtUtil {

    @Value("${JWT_SECRET}")
    private String SECRET_KEY;

    @Value("${JWT_EXPIRES_IN}")
    private String EXPIRES_IN;
    
    public String generateToken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String,Object> claims, String email){
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(email)
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + parseExpiration(EXPIRES_IN)))
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, SECRET_KEY)
            .compact();

    }

    private long parseExpiration(String expiresIn) {
        // Remove any whitespace
        expiresIn = expiresIn.trim();
        
        // Check if it ends with a time unit (d for days, h for hours, m for minutes, s for seconds)
        if (expiresIn.matches("\\d+[dhms]")) {
            long value = Long.parseLong(expiresIn.substring(0, expiresIn.length() - 1));
            char unit = expiresIn.charAt(expiresIn.length() - 1);
            
            switch (unit) {
                case 'd': return value * 24 * 60 * 60 * 1000; // days to milliseconds
                case 'h': return value * 60 * 60 * 1000;      // hours to milliseconds
                case 'm': return value * 60 * 1000;           // minutes to milliseconds
                case 's': return value * 1000;                // seconds to milliseconds
                default: throw new IllegalArgumentException("Invalid time unit: " + unit);
            }
        }
        
        // If no unit, assume it's milliseconds
        return Long.parseLong(expiresIn);
    }


    private Claims extractAllClaims(String token){
        return Jwts.parser()
        .setSigningKey(SECRET_KEY)
        .parseClaimsJws(token).getBody();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }


    public String extractEmail(String token){
        return extractClaim(token, Claims::getSubject);
    }

    private Boolean isTokenExpired(String token){
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }


    public Boolean validateToken(String token, UserDetails userDetails){
        final String email = extractEmail(token);
        return (email.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
