package se.iths.martin.authserverprojekt2.dto;

import java.util.List;

public record MeResponseDto(
        String username,
        List<String> roles
) {
}
