package com.example.authz.web;

import jakarta.validation.constraints.NotEmpty;

import java.util.List;

/** Body for POST /api/authz/roles/permissions. Blank entries are ignored. */
public record RolesRequest(@NotEmpty List<String> roles) {
}
