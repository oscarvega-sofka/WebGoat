/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * Negative security tests for {@code POST /service/admin/users/{username}/reset-password}.
 *
 * <p>Unlike {@link AdminControllerTest} (standalone MockMvc, no security), these tests run through
 * the real Spring Security filter chain and method security, so each one fails when the control it
 * covers is removed:
 *
 * <ul>
 *   <li>Authentication – anonymous callers are rejected with 401.
 *   <li>Authorization – authenticated users without {@code WEBGOAT_ADMIN} get 403.
 *   <li>Input validation – a malformed username is rejected with 400 before reaching the service.
 *   <li>Error handling – an internal failure returns a bare 500 that leaks no internal details.
 * </ul>
 */
class AdminResetPasswordNegativeTest extends LessonTest {

  private static final String RESET_URL = "/service/admin/users/{username}/reset-password";
  private static final String TARGET_USER = "victim-user";

  @MockitoSpyBean private UserService userService;

  private MockMvc securedMvc;

  @BeforeEach
  void setUpSecurity() {
    securedMvc = MockMvcBuilders.webAppContextSetup(wac).apply(springSecurity()).build();
  }

  private static SimpleGrantedAuthority authority(String name) {
    return new SimpleGrantedAuthority(name);
  }

  /** Authentication: without a session the request never reaches the password reset. */
  @Test
  void authentication_anonymousCallerIsRejected() throws Exception {
    securedMvc
        .perform(
            post(RESET_URL, TARGET_USER)
                .with(anonymous())
                .header("X-Requested-With", "XMLHttpRequest"))
        .andExpect(status().isUnauthorized())
        .andExpect(content().string(not(containsString("temporaryPassword"))));

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  /** Authorization: a logged-in regular user cannot reset someone else's password. */
  @Test
  void authorization_regularUserIsForbidden() throws Exception {
    securedMvc
        .perform(
            post(RESET_URL, TARGET_USER)
                .with(user("regular-user").authorities(authority(WebGoatUser.ROLE_USER))))
        .andExpect(status().isForbidden())
        .andExpect(content().string(not(containsString("temporaryPassword"))));

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  /** Input validation: a username outside the allowed format is rejected with 400. */
  @Test
  void inputValidation_malformedUsernameIsRejected() throws Exception {
    securedMvc
        .perform(
            post(RESET_URL, "tom' OR '1'='1")
                .with(user("admin-user").authorities(authority(WebGoatUser.ROLE_ADMIN))))
        .andExpect(status().isBadRequest())
        .andExpect(content().string(not(containsString("temporaryPassword"))));

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  /** Error handling: an internal failure yields a generic 500 without internal details. */
  @Test
  void errorHandling_internalFailureDoesNotLeakDetails() throws Exception {
    doThrow(
            new DataAccessResourceFailureException(
                "Connection refused: jdbc:hsqldb:file:/opt/webgoat/data/webgoat"))
        .when(userService)
        .resetPassword(eq(TARGET_USER), anyString());

    securedMvc
        .perform(
            post(RESET_URL, TARGET_USER)
                .with(user("admin-user").authorities(authority(WebGoatUser.ROLE_ADMIN))))
        .andExpect(status().isInternalServerError())
        .andExpect(content().string(not(containsString("jdbc"))))
        .andExpect(content().string(not(containsString("Exception"))))
        .andExpect(content().string(not(containsString("temporaryPassword"))));
  }
}
