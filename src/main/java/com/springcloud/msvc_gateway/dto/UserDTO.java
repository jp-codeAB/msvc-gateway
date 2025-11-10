package com.springcloud.msvc_gateway.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDTO {
    private Long id;
    private String username;
    private String rol;
    private String email;
}
