package com.geekcatalog.api.infra.security;

import com.geekcatalog.api.domain.user.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

@Component
@AllArgsConstructor
public class SecurityFilter extends OncePerRequestFilter {
    private final TokenService tokenService;
    private final AuthenticateUserWithValidJwt authenticateUserWithValidJwt;

    // Cache para armazenar usuários autenticados
    private final ConcurrentHashMap<String, User> userCache = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = getAccessToken(request);

        if (accessToken != null && tokenService.isAccessTokenValid(accessToken)) {
            authenticateUser(tokenService.getSubject(accessToken));
        }
        filterChain.doFilter(request, response);
    }

    private void authenticateUser(String subject) {
        User user = getUserFromCacheOrDb(subject);

        if (user != null) {
            // avisa ao Spring que o usuário está autenticado
            var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }

    private User getUserFromCacheOrDb(String subject) {
        // Verifica se o usuário está no cache, se não tiver busca no banco de dados
        return userCache.computeIfAbsent(subject, authenticateUserWithValidJwt::findUserAuthenticated);
    }

    private String getAccessToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }
}
