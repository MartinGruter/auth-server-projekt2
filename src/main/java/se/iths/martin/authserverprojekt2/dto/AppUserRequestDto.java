package se.iths.martin.authserverprojekt2.dto;

import jakarta.validation.constraints.NotBlank;

public record AppUserRequestDto(
        @NotBlank(message = "Username can't be null.")
        String username,
        @NotBlank(message = "Password can't be null.")
        String password
) {
}
