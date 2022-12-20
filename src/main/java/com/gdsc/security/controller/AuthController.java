package com.gdsc.security.controller;

import com.gdsc.security.domain.entity.Role;
import com.gdsc.security.domain.entity.User;
import com.gdsc.security.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;
import java.util.Set;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping
    public String index() {
        return "메인 페이지";
    }

    @GetMapping("/user")
    public String user() {
        return "유저 페이지";
    }

    @GetMapping("/admin")
    public String admin() {
        return "어드민 페이지";
    }

    // @AuthenticationPrincipal로 필터링된 UserDetails를 불러올 수 있음.
    @GetMapping("/myinfo")
    public String myInfo(@AuthenticationPrincipal User user) {
        return (user == null) ? "유저 정보 없음" : user.getAuthorities().toString();
    }

    @GetMapping("/signup")
    public String signUp(@RequestParam String username, @RequestParam String password, @RequestParam boolean isAdmin) {
        Set<Role> set = new HashSet<>();
        set.add(Role.ROLE_USER);

        if (isAdmin) set.add(Role.ROLE_ADMIN);

        User user = User.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .roles(set)
                .build();

        userRepository.saveAndFlush(user);

        return "회원가입 성공";
    }
}
