package com.arka.gateway_service.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

@Component
public class AdminAuthorizationFilterGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {

    public AdminAuthorizationFilterGatewayFilterFactory(){
        super(Object.class);
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {

            ServerHttpRequest request= exchange.getRequest();

            String roles=request.getHeaders().getFirst("X-User-Roles");
            if (roles==null){
                ServerHttpResponse response= exchange.getResponse();
                response.setStatusCode(HttpStatus.FORBIDDEN);
                return response.setComplete();
            }

            if (!roles.contains("ROLE_ADMINISTRADOR")) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.FORBIDDEN);
                return response.setComplete();
            }

            return chain.filter(exchange);
        };
    }
}
