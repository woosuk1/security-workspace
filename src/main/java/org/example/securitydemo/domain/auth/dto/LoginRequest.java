package org.example.securitydemo.domain.auth.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Pattern;
import lombok.ToString;
import lombok.Value;
import jakarta.validation.constraints.NotBlank;

@Value
public class LoginRequest {

    /* TODO. 유효성 검사 추가 예정*/
    @NotBlank(message = "Username is mandatory")
    @Email(message = "올바른 이메일 형식이 아닙니다.")
    String username;  // 불변 필드로 설정

    @ToString.Exclude  // 비밀번호는 toString()에 포함되지 않도록 설정
    @NotBlank(message = "Password is mandatory")
    @Size(min = 8, max = 20, message = "비밀번호는 8자 이상 20자 이하로 입력해야 합니다.")
    @Pattern(regexp = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*\\W).+",
            message = "비밀번호는 영문 대소문자, 숫자, 특수문자를 포함해야 합니다.")
    String password;   // 불변 필드로 설정


    @JsonCreator
    public LoginRequest(@JsonProperty("username") String username,
                        @JsonProperty("password") String password) {
        this.username = username;
        this.password = password;
    }


    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

}