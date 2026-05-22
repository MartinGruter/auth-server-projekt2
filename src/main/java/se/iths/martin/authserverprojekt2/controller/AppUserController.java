package se.iths.martin.authserverprojekt2.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import se.iths.martin.authserverprojekt2.dto.AppUserRequestDto;
import se.iths.martin.authserverprojekt2.dto.AppUserResponseDto;
import se.iths.martin.authserverprojekt2.service.AppUserService;

import java.util.List;

@RestController
@RequestMapping("/appusers")
@RequiredArgsConstructor
public class AppUserController {
    private final AppUserService appUserService;

    @GetMapping
    public List<AppUserResponseDto> findAllUsers() {
        return appUserService.findAll();
    }

    @GetMapping("/{id}")
    public AppUserResponseDto findById(@PathVariable Long id) {
        return appUserService.findById(id);
    }

    @Valid
    @PostMapping
    public AppUserResponseDto create(@RequestBody AppUserRequestDto appUserRequestDto) {
        return appUserService.create(appUserRequestDto);
    }
}
