package com.example.search;

import io.swagger.annotations.ApiModelProperty;

/**
 * Login request DTO. The `example = "..."` strings are Swagger/OpenAPI
 * documentation metadata, NOT runtime default values.
 * Scanner may flag them as hardcoded secrets; Validator should exclude
 * as `swagger_example`.
 */
public class LoginVo {

    @ApiModelProperty(value = "Username", example = "admin")
    private String username;

    @ApiModelProperty(value = "Password", example = "admin123")
    private String password;

    public String getUsername() { return username; }
    public void setUsername(String u) { this.username = u; }
    public String getPassword() { return password; }
    public void setPassword(String p) { this.password = p; }
}
