/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.mailbox;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.time.LocalDateTime;

/**
 * Request body for delivering mail. Only the fields a sender may choose are bound; server-controlled
 * fields such as {@code id}, {@code time} and {@code read} are never taken from the client, so a
 * request cannot overwrite an existing message (mass assignment, CWE-915).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record IncomingEmail(String sender, String recipient, String title, String contents) {

  Email toEmail() {
    return Email.builder()
        .sender(sender)
        .recipient(recipient)
        .title(title)
        .contents(contents)
        .time(LocalDateTime.now())
        .read(false)
        .build();
  }
}
