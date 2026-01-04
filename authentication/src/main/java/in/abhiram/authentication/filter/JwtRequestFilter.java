package in.abhiram.authentication.filter;

import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import in.abhiram.authentication.service.CustomUserDetailsService;
import in.abhiram.authentication.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;


@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final CustomUserDetailsService customUserDetailsService;

    private final JwtUtil jwtUtil;


    private static final List<String> PUBLIC_URLS=List.of("/profile/register", "/profile/login", "/profile/send-reset-otp", "/profile/send-password-reset");

    @Override
    protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain filterChain)throws java.io.IOException, jakarta.servlet.ServletException {
        
        String path = request.getServletPath();
        System.out.println("JwtRequestFilter - Path: " + path + " | Method: " + request.getMethod());
        System.out.println("JwtRequestFilter - Is public URL? " + PUBLIC_URLS.contains(path));
        
        if(PUBLIC_URLS.contains(path)){
            System.out.println("JwtRequestFilter - Allowing public URL");
            filterChain.doFilter(request, response);
            return;
        }
        
        String jwt = null;
        String email = null;

        // Try to get JWT from Authorization header
        final String authorizationHeader = request.getHeader("Authorization");
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            jwt = authorizationHeader.substring(7);
            System.out.println("JwtRequestFilter - Token from Authorization header");
        }

        // If not in header, try to get from cookie
        if(jwt == null){
            Cookie[] cookies = request.getCookies();
            if(cookies != null){
                for(Cookie cookie : cookies){
                    if(cookie.getName().equals("jwtToken")){
                        jwt = cookie.getValue();
                        System.out.println("JwtRequestFilter - Token from cookie");
                        break;
                    }
                }
            }
        }

        // Validate and authenticate
        if(jwt != null){
            try {
                email = jwtUtil.extractEmail(jwt);
                System.out.println("JwtRequestFilter - Extracted email: " + email);

                if(email != null && SecurityContextHolder.getContext().getAuthentication() == null){
                    UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);

                    if(jwtUtil.validateToken(jwt, userDetails)){
                        UsernamePasswordAuthenticationToken authToken = 
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                        System.out.println("JwtRequestFilter - Authentication successful for: " + email);
                    } else {
                        System.out.println("JwtRequestFilter - Token validation failed");
                    }
                }
            } catch (Exception e) {
                System.out.println("JwtRequestFilter - Error processing token: " + e.getMessage());
            }
        } else {
            System.out.println("JwtRequestFilter - No JWT token found");
        }
        
        filterChain.doFilter(request, response);
    }

}