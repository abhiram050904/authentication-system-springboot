package in.abhiram.authentication.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;


    @Value("${spring.mail.properties.mail.smtp.from}")
    private String fromEmail;

    public void sendEmail(String toEmail, String subject, String body) {
        var message = mailSender.createMimeMessage();
        try {
            var messageHelper = new org.springframework.mail.javamail.MimeMessageHelper(message, true);
            messageHelper.setFrom(fromEmail);
            messageHelper.setTo(toEmail);
            messageHelper.setSubject(subject);
            messageHelper.setText(body, true); // true indicates HTML content
            mailSender.send(message);
        } catch (Exception e) {
            e.printStackTrace();
            // Handle exception or log error
        }
    }

    
}
