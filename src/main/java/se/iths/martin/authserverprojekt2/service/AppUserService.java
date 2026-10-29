package se.iths.martin.authserverprojekt2.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import se.iths.martin.authserverprojekt2.dto.AppUserRequestDto;
import se.iths.martin.authserverprojekt2.dto.AppUserResponseDto;
import se.iths.martin.authserverprojekt2.exception.UserNotFoundException;
import se.iths.martin.authserverprojekt2.mapper.AppUserMapper;
import se.iths.martin.authserverprojekt2.model.AppUser;
import se.iths.martin.authserverprojekt2.repository.AppUserRepository;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AppUserService {

    private final AppUserMapper appUserMapper;
    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Hämtar alla användare och mappar dom till DTO
     *
     * @return en lista av alla users som AppUserResponseDto
     */
    public List<AppUserResponseDto> findAll() {
        List<AppUser> appUsers = appUserRepository.findAll();
        return appUsers.stream().map(appUserMapper::toDto).toList();
    }

    /**
     * Hämtar en användare med specifikt id
     *
     * @param id användarens id
     * @return användare som en AppUserResponseDto
     */
    public AppUserResponseDto findById(Long id) {
        AppUser appuser = getAppUser(id);
        return appUserMapper.toDto(appuser);
    }

    /**
     * Hittar användare med id eller kastar exception om användare inte finns
     *
     * @param id användarens id
     * @return hämtar en användare med specifikt id
     */
    private AppUser getAppUser(Long id) {
        return appUserRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found."));
    }

    /**
     * Skapar en användare med hashat lösenord och role är alltid satt till USER
     *
     * @param appUserRequestDto username och password somn ny användare
     * @return sparad användare som en AppUserResponseDto
     */
    public AppUserResponseDto create(AppUserRequestDto appUserRequestDto) {
        AppUser appUser = appUserMapper.toEntity(appUserRequestDto);
        String encodedPassword = passwordEncoder.encode(appUser.getPassword());
        appUser.setPassword(encodedPassword);
        appUser.setRole("USER");
        AppUser saved = appUserRepository.save(appUser);
        return appUserMapper.toDto(saved);
    }

}
