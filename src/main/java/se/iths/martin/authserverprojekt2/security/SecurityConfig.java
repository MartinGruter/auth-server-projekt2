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
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import se.iths.martin.authserverprojekt2.exception.UserNotFoundException;
import se.iths.martin.authserverprojekt2.model.AppUser;
import se.iths.martin.authserverprojekt2.repository.AppUserRepository;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;


@Component
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.cors.allowed-origins}")
    private String allowedOrigins;

    private final String jwtPublicKey;
    private final String jwtPrivateKey;
    private final String jwtKeyId;

    public SecurityConfig(
            @Value("${app.jwt.public-key:}") String jwtPublicKey,
            @Value("${app.jwt.private-key:}") String jwtPrivateKey,
            @Value("${app.jwt.key-id}") String jwtKeyId
    ) {
        this.jwtPublicKey = jwtPublicKey;
        this.jwtPrivateKey = jwtPrivateKey;
        this.jwtKeyId = jwtKeyId;
    }

    /**
     * Skapar ett keyPair från miljövariablerna JWT_PUBLIC_KEY och JWT_PRIVATE_KEY
     * som anvönds för att signera token
     *
     * @return keyPair från nycklarna
     * @throws Exception om private key eller public key saknas
     */
    @Bean
    public KeyPair keyPair() throws Exception {
        if (StringUtils.hasText(jwtPrivateKey) && StringUtils.hasText(jwtPublicKey)) {
            String cleanPrivateKey = jwtPrivateKey
                    .trim()
                    .replace("\\n", "")
                    .replaceAll("\\s", "");
            String cleanPublicKey = jwtPublicKey
                    .trim()
                    .replace("\\n", "")
                    .replaceAll("\\s", "");
            byte[] privateBytes =
                    Base64.getDecoder().decode(cleanPrivateKey);
            byte[] publicBytes =
                    Base64.getDecoder().decode(cleanPublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes));
            return new KeyPair(publicKey, privateKey);
        }
        throw new IllegalArgumentException("Private or public key is missing.");
    }

    /**
     * Skapar en JWKSource från keyPair där rsaKey krypterar keyPair
     *
     * @param keyPair den publika och privata nyckeln
     * @return en immutableJWKSet som inte går att ändra efter den skapats
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(jwtKeyId)
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /**
     * Metoden skapar den JwtEncoder som auth-servern använder för att skapa och
     * signera JWT-tokens vid inloggning.
     *
     * @param jwkSource källan till att signera nyckeln
     * @return en JwtEncoder som signerar token med konfigurerad nyckel
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Skapar JwtDecoder som verifierar JWTs med hjälp av RSA public key
     *
     * @param keyPair som används för verifiering
     * @return en JwtDecoder som validerar token signatur och expiry
     */
    @Bean
    public JwtDecoder jwtDecoder(KeyPair keyPair) {
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
    }

    /**
     * Verifierar en users credentials under login
     *
     * @param authenticationConfiguration Spring Securites authentication konfiguration
     * @return den konfigurerade AuthenticationManager
     * @throws Exception om manager inte kan bli skapad
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration
    ) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Skapar en PasswordEncoder som hashar lösenord med BCrypt
     *
     * @return en BCrypt med PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Definierar hur Spring Security laddar en användare under login
     * genom att söka upp användare i databasen
     *
     * @param appUserRepository repository som hittar användare med username
     * @return en UserDetailsService som returnerar användares username, hashade password och role
     */
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

    /**
     * Konfigurerar security regler för alla endpoints
     *
     * @param httpSecurity som vi får av Spring Security
     * @return den konfigurerade SecurityFilterChain
     * @throws Exception om security konfigurationen inte kan byggas
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .cors(Customizer.withDefaults())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/auth/login", "/auth/jwks").permitAll()
                        .requestMatchers(HttpMethod.POST, "/appusers").permitAll()
                        .requestMatchers(HttpMethod.GET, "/appusers/**").permitAll()
                        .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**").permitAll()
                        .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable);
        return httpSecurity.build();
    }

    /**
     * Konfigurerar CORS så att den tillåter frontend att kalla på servern
     *
     * @return CORS konfigurationen appliceras till alla paths
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(
                allowedOrigins.split(",")));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
