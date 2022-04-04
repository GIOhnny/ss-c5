package ro.giohnnysoftware.ssc5.security.providers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import ro.giohnnysoftware.ssc5.security.authentication.CustomAuthentication;

@Component
public class CustomAutheticationProvider implements AuthenticationProvider {

    @Value("${key}")
    private String key;

    @Override
    public Authentication authenticate(Authentication authentication) {
        String requestKey = authentication.getName();
        if (requestKey.equals(key)) {
           var a = new CustomAuthentication(null, null, null);
           return a;
        } else {
            throw new BadCredentialsException("Bau!");
        }

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthentication.class.equals(authentication);
    }
}
