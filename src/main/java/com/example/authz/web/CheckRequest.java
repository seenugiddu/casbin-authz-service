package com.example.authz.web;

import jakarta.validation.constraints.NotBlank;

public record CheckRequest(@NotBlank String resource, @NotBlank String action) {
}
