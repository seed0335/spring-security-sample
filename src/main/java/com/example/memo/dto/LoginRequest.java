package com.example.memo.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record LoginRequest(@JsonProperty("username") String email, String password) {
}
