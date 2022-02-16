package com.example.iframewithheaders;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@SpringBootApplication
@EnableConfigurationProperties({IframeWithHeadersApplication.AppConfigProps.class})
public class IframeWithHeadersApplication {

    public static void main(String[] args) {
        SpringApplication.run(IframeWithHeadersApplication.class, args);
    }

    @Controller
    @RequiredArgsConstructor
    public static class FramesController {

        private final AppConfigProps appConfigProps;

        @GetMapping("/")
        public String framer(Model model) {

            model.addAttribute("frameePort", appConfigProps.getFrameePort());


            return "framer";
        }

        @GetMapping("/framee")
        public String framee(HttpServletRequest req, Model model) {

            var headerValue = req.getHeader("X-MADE-UP-HEADER");

            model.addAttribute("headerValue", headerValue);

            return "framee";
        }

        @GetMapping("/jwt")
        public String jwtFramer(Model model) {

            final LocalDateTime createdAt = LocalDateTime.now();
            final LocalDateTime expiresAt = createdAt.plusSeconds(10);

            final String jwt = JWT.create()
                .withIssuer("framer")
                .withSubject("framer-subject")
                .withArrayClaim("roles", new String[]{"jwt-framee"})
                .withIssuedAt(Timestamp.valueOf(createdAt))
                .withExpiresAt(Timestamp.valueOf(expiresAt))
                .sign(Algorithm.HMAC512(appConfigProps.getJwtSecret()));

            model.addAttribute("jwt", jwt);
            model.addAttribute("frameePort", appConfigProps.getFrameePort());


            return "jwt-framer";
        }

        @GetMapping("/jwt-framee")
        public String jwtFramee(HttpServletRequest req, Model model, Authentication authentication) {

            var jwt = req.getHeader("Authorization");

            model.addAttribute("jwt", jwt);
            model.addAttribute("authentication", authentication);

            return "jwt-framee";
        }

    }

    @Configuration
    @RequiredArgsConstructor
    public static class AppConf implements WebMvcConfigurer {

        private final AppConfigProps appConfigProps;

        @Override
        public void addCorsMappings(CorsRegistry registry) {
            registry.addMapping("/**")
                .allowedOrigins("http://localhost:%s".formatted(appConfigProps.getFramerPort()))
                .allowedMethods("GET");
        }
    }

    @ConfigurationProperties("app")
    @Data
    public static class AppConfigProps {
        private String jwtSecret;
        private String jwtExpiresAtOffsetSeconds;
        private Integer framerPort;
        private Integer frameePort;
    }

    @Configuration
    @EnableWebSecurity
    @RequiredArgsConstructor
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {

        private final AppConfigProps appConfigProps;

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.cors().and().csrf().disable()
                .authorizeHttpRequests()
                .antMatchers("/")
                    .permitAll()
                .and()
                .antMatcher("/jwt-framee")
                    .authorizeHttpRequests()
                    .anyRequest()
                    .authenticated()
                .and()
                .addFilter(new JwtAuthorizationFilter(appConfigProps.getJwtSecret(), authenticationManager()))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        }
    }

    public static class JwtAuthorizationFilter extends BasicAuthenticationFilter {

        private final String secret;

        public JwtAuthorizationFilter(String secret, AuthenticationManager authenticationManager) {
            super(authenticationManager);
            this.secret = secret;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

            final String authorizationHeader = request.getHeader("Authorization");
            if (Objects.isNull(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
                chain.doFilter(request, response);
                return;
            }

            final DecodedJWT decodedJwt = JWT.require(Algorithm.HMAC512(secret.getBytes()))
                .build()
                .verify(authorizationHeader.replace("Bearer ", ""));

            var claims = decodedJwt.getClaim("roles");
            final List<SimpleGrantedAuthority> collect = claims.asList(String.class).stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

            var authenticationToken = new UsernamePasswordAuthenticationToken(
                decodedJwt.getSubject(),
                null,
                collect);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            super.doFilterInternal(request, response, chain);
        }
    }

}
