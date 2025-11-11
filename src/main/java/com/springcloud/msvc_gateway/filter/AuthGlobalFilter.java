package com.springcloud.msvc_gateway.filter;

import com.springcloud.msvc_gateway.dto.UserDTO;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Instant;
import java.util.List;

@Component
public class AuthGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(AuthGlobalFilter.class);
    private final WebClient.Builder webClientBuilder;
    private static final String AUTH_HEADER = HttpHeaders.AUTHORIZATION;
    private static final String BEARER_PREFIX = "Bearer ";

    private static final List<String> PUBLIC_ROUTES = List.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/validate-token"
    );

    public AuthGlobalFilter(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();

        if (PUBLIC_ROUTES.contains(path)) {
            log.info("Ruta pública permitida: {}", path);
            return chain.filter(exchange);
        }

        String token = request.getHeaders().getFirst(AUTH_HEADER);

        if (token == null || !token.startsWith(BEARER_PREFIX)) {
            log.warn("Acceso denegado a ruta protegida {}: Token de autenticación ausente o formato inválido.", path);
            return errorResponse(exchange, HttpStatus.UNAUTHORIZED, "Missing Token", "Authentication token is missing or invalid format.");
        }
        String jwt = token.substring(BEARER_PREFIX.length());
        return webClientBuilder.build()
                .get()
                .uri("lb://msvc-auth/api/auth/validate-token?token=" + jwt)
                .retrieve()
                .bodyToMono(UserDTO.class)
                .flatMap(userDto -> {
                    log.info("Token validado con éxito. Roles: {}", userDto.getRol());
                    ServerHttpRequest mutatedRequest = request.mutate()
                            .header("X-User-ID", String.valueOf(userDto.getId()))
                            .header("X-User-Roles", userDto.getRol())
                            .header("X-User-Email", userDto.getEmail())
                            .build();

                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                .onErrorResume(Exception.class, e -> {
                    if (e instanceof WebClientResponseException wcre) {
                        HttpStatusCode upstreamStatus = wcre.getStatusCode();

                        log.error("FALLO DE VALIDACIÓN JWT (msvc-auth). Status: {}, Body: {}",
                                upstreamStatus.value(), wcre.getResponseBodyAsString(), wcre);

                        if (upstreamStatus.is4xxClientError()) {
                            String detail = "Authentication token is invalid or expired.";
                            return errorResponse(exchange, HttpStatus.UNAUTHORIZED, "Unauthorized", detail);
                        }

                        if (upstreamStatus.is5xxServerError()) {
                            String detail = "Authentication service encountered an internal error.";
                            return errorResponse(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "Upstream Server Error", detail);
                        }

                    } else {

                        log.error("FALLO CRÍTICO en WebClient o Conexión a msvc-auth: {}", e.getMessage(), e);
                        String detail = "The authentication service is temporarily unavailable. Please try again later.";
                        return errorResponse(exchange, HttpStatus.SERVICE_UNAVAILABLE, "Service Unavailable", detail);
                    }

                    String detail = "An unexpected error occurred in the Gateway filter process.";
                    return errorResponse(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "Internal Gateway Error", detail);
                });
    }

    private Mono<Void> errorResponse(ServerWebExchange exchange, HttpStatus status, String errorType, String message) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String jsonBody = String.format("{\"timestamp\":\"%s\", \"status\":%d, \"error\":\"%s\", \"message\":\"%s\", \"path\":\"%s\"}",
                Instant.now(),
                status.value(),
                errorType,
                message,
                exchange.getRequest().getPath().value());

        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(jsonBody.getBytes()))
        );
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}