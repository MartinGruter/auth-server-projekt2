package se.iths.martin.authserverprojekt2.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import se.iths.martin.authserverprojekt2.exception.UserNotFoundException;
import se.iths.martin.authserverprojekt2.model.AppUser;
import se.iths.martin.authserverprojekt2.repository.AppUserRepository;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


@Component
@EnableWebSecurity
public class SecurityConfig {

    private final String publicKeyPath;
    private final String privateKeyPath;
    private final String jwtKeyId;

    public SecurityConfig(
            @Value("${app.jwt.public-key:}") String jwtPublicKey,
            @Value("${app.jwt.private-key:}") String privateKeyPath,
            @Value("${app.jwt.key-id}") String jwtKeyId
    ) {
        this.publicKeyPath = jwtPublicKey;
        this.privateKeyPath = privateKeyPath;
        this.jwtKeyId = jwtKeyId;
    }

    @Bean
    public KeyPair keyPair() throws Exception {
        String privatePem = new String(Files.readAllBytes(Paths.get(privateKeyPath)));
        String cleanPrivateKey = privatePem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\s+", "");

        // Read public key from file
        String publicPem = new String(Files.readAllBytes(Paths.get(publicKeyPath)));
        String cleanPublicKey = publicPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\s+", "");

        byte[] privateBytes =
                Base64.getDecoder().decode(cleanPrivateKey);
        byte[] publicBytes =
                Base64.getDecoder().decode(cleanPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes));
        return new KeyPair(publicKey, privateKey);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(jwtKeyId)
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration
    ) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(AppUserRepository appUserRepository) {
        return username -> {
            AppUser appUser = appUserRepository.findByUsername(username)
                    .orElseThrow(() -> new UserNotFoundException("User not found."));
            return User.builder()
                    .username(appUser.getUsername())
                    .password(appUser.getPassword())
                    .roles(appUser.getRole())
                    .build();
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/auth/login", "/auth/jwks").permitAll()
                        .requestMatchers(HttpMethod.POST, "/appusers").permitAll()
                        .requestMatchers(HttpMethod.GET, "/appusers/**").permitAll()
                        .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**").permitAll()
                        .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable);
        return httpSecurity.build();
    }
}
