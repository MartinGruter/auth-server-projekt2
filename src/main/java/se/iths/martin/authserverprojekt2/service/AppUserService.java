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


    public List<AppUserResponseDto> findAll() {
        List<AppUser> appUsers = appUserRepository.findAll();
        return appUsers.stream().map(appUserMapper::toDto).toList();
    }

    public AppUserResponseDto findById(Long id) {
        AppUser appuser = getAppUser(id);
        return appUserMapper.toDto(appuser);
    }

    private AppUser getAppUser(Long id) {
        return appUserRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found."));
    }

    public AppUserResponseDto create(AppUserRequestDto appUserRequestDto) {
        AppUser appUser = appUserMapper.toEntity(appUserRequestDto);
        String encodedPassword = passwordEncoder.encode(appUser.getPassword());
        appUser.setPassword(encodedPassword);
        appUser.setRole("USER");
        AppUser saved = appUserRepository.save(appUser);
        return appUserMapper.toDto(saved);
    }

}
