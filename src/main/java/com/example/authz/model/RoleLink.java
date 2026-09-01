package com.example.authz.model;

/**
 * One Casbin "g" rule: {@code role} inherits every policy of {@code inheritsFrom}.
 */
public record RoleLink(String role, String inheritsFrom) {
}
