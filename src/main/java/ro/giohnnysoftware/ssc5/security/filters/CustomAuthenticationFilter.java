package ro.giohnnysoftware.ssc5.security.filters;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import ro.giohnnysoftware.ssc5.security.authentication.CustomAuthentication;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFilter implements Filter {
    //puteam folosi extends OncePerRequestFilter care are in intrare HttpServletRequest si Response si nu
    //mai era nevoie sa facem cast

    @Autowired
    private AuthenticationManager manager;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        var httpRequest = (HttpServletRequest) request;
        var httpResponse = (HttpServletResponse) response;
        String authorization = httpRequest.getHeader("Authorization");
        //authorization logic
        var a = new CustomAuthentication(authorization, null);

        try {
            Authentication result = manager.authenticate(a);

            if (result.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(result);
                chain.doFilter(request, response);
            }
            else {
                httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            }
        } catch (AuthenticationException e) {
            httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
