package org.example.securitydemo.domain.config.openapi;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@OpenAPIDefinition(
        info = @Info(
                title = "security api",
                description = "security api",
                version = "v1"
        ),security = {@SecurityRequirement(name = "Bearer Authentication")}
)
@SecurityScheme(
        name = "Bearer Authentication",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT"
)
@Configuration
public class OpenAPIConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI();
    }

//    @Bean
//    public GroupedOpenApi userApi() {
//        return GroupedOpenApi.builder()
//                .group("API")
//                .pathsToMatch("/api/**") // 특정 경로만 포함
//                .build();
//    }

}

