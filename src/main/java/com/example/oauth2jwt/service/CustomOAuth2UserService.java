package com.example.oauth2jwt.service;

import com.example.oauth2jwt.dto.*;
import com.example.oauth2jwt.entity.User;
import com.example.oauth2jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        log.info("user = {}", oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if(registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        } else {
            return null;
        }

        String username = oAuth2Response.getProvider() + "_" + oAuth2Response.getProviderId();
        User existsData = userRepository.findByUsername(username);

        if(existsData == null) {
            User user = User.builder()
                    .username(username)
                    .email(oAuth2Response.getEmail())
                    .role("ROLE_USER")
                    .name(oAuth2Response.getName())
                    .build();

            userRepository.save(user);

            UserDto userDto = UserDto.builder()
                    .username(username)
                    .role("ROLE_USER")
                    .name(oAuth2User.getName())
                    .build();

            return new CustomOAuth2User(userDto);
        } else {

            existsData.setEmail(oAuth2Response.getEmail());
            userRepository.save(existsData);

            UserDto userDto = UserDto.builder()
                    .username(existsData.getUsername())
                    .name(oAuth2Response.getName())
                    .role(existsData.getRole())
                    .build();

            return new CustomOAuth2User(userDto);
        }

    }
}
