package se.iths.martin.authserverprojekt2.mapper;

import org.mapstruct.Mapper;
import se.iths.martin.authserverprojekt2.dto.AppUserRequestDto;
import se.iths.martin.authserverprojekt2.dto.AppUserResponseDto;
import se.iths.martin.authserverprojekt2.model.AppUser;

@Mapper(componentModel = "spring")
public interface AppUserMapper {
    AppUser toEntity(AppUserRequestDto appUserRequestDto);

    AppUserResponseDto toDto(AppUser appUser);
}
