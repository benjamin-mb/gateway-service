package com.arka.gateway_service.filter;

import com.arka.gateway_service.token.ValidateToken;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationFilterGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {

    private final ValidateToken validateToken;

    public JwtAuthenticationFilterGatewayFilterFactory(ValidateToken validateToken) {
        super(Object.class);
        this.validateToken = validateToken;
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            ServerHttpRequest request=exchange.getRequest();

            if (!request.getHeaders().containsKey("Authorization")) {
                ServerHttpResponse response= exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }

            String authHeader=request.getHeaders().getFirst("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")){
                ServerHttpResponse response= exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }

            String token=authHeader.substring(7);

            try{
                String username=validateToken.extractUserName(token);

                if (!validateToken.isTokenValid(token,username)){
                    ServerHttpResponse response= exchange.getResponse();
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    return response.setComplete();
                }

                String roles= validateToken.extractRole(token);

                ServerHttpRequest modifiedRequest=exchange.getRequest().mutate()
                        .header("X-User-Email", username)
                        .header("X-User-Roles",roles)
                        .build();

                return chain.filter(exchange.mutate().request(modifiedRequest).build());
            }catch (Exception e){
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }
        };
    }
}
