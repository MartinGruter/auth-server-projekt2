package se.iths.martin.authserverprojekt2.dto;

import java.util.List;

public record TokenResponseDto(
        String accessToken,
        Long expiresIn,
        String subject,
        List<String> roles
) {
}
