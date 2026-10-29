package se.iths.martin.authserverprojekt2.controller;


import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import se.iths.martin.authserverprojekt2.dto.AppUserRequestDto;
import se.iths.martin.authserverprojekt2.dto.MeResponseDto;
import se.iths.martin.authserverprojekt2.dto.TokenResponseDto;
import se.iths.martin.authserverprojekt2.service.AuthService;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Loggar in en användare med username och password
     *
     * @param appUserRequestdto Kräver username och password
     * @return En inloggad anvöndare
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(
            @Valid @RequestBody AppUserRequestDto appUserRequestdto) {
        return ResponseEntity.ok(authService.login(appUserRequestdto));
    }

    /**
     * skapar en publicJwks som publicerar auth-serverns publika nyckel som JWKS
     *
     * @return publika nyckeln i formatet JWKS
     */
    @GetMapping("/jwks")
    public ResponseEntity<Map<String, Object>> publicJwks() {
        return ResponseEntity.ok(authService.publicJwkSet());
    }

    /**
     * Syftet är att fronted ska kunna återställa anvöndare efter omladdning
     *
     * @param jwt ger tillgång till innehållet i den verifierade token
     * @return en MeResponseDto med username och role
     */
    @GetMapping("/me")
    public ResponseEntity<MeResponseDto> me(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(
                new MeResponseDto(jwt.getSubject(), jwt.getClaimAsStringList("roles")));
    }
}
