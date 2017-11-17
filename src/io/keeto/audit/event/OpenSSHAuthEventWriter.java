/*
 * Copyright (C) 2017 Sebastian Roland <seroland86@gmail.com>
 *
 * This file is part of Keeto.
 *
 * Keeto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Keeto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Keeto.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.keeto.audit.event;

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.OffsetDateTime;

import org.syslog_ng.LogMessage;

import io.keeto.audit.util.KeetoAuditUtil;

public class OpenSSHAuthEventWriter implements EventWriter {

  private final String insertNewAuthPs = "INSERT INTO openssh_auth VALUES (?, ?, ?, ?, ?, ?)";

  private Connection conn;

  public OpenSSHAuthEventWriter(Connection conn) {
    super();
    if (conn == null) {
      throw new IllegalArgumentException("conn == null");
    }
    this.conn = conn;
  }

  @Override
  public void write(LogMessage logMessage) throws SQLException {
    if (logMessage == null) {
      throw new IllegalArgumentException("logMessage == null");
    }
    PreparedStatement insertNewAuth = conn.prepareStatement(insertNewAuthPs);

    BigDecimal sessionId = KeetoAuditUtil.getSessionIdFromDb(conn, logMessage);
    if (sessionId == null) {
      throw new IllegalStateException("session id not found");
    }
    OffsetDateTime timestamp = KeetoAuditUtil.timestampFromLogMessage(logMessage);
    String event = logMessage.getValue("KEETO_AUDIT_EVENT");
    String username = logMessage.getValue("OPENSSH_USERNAME");
    String hashAlgo = logMessage.getValue("OPENSSH_HASH_ALGO");
    String fingerprint = logMessage.getValue("OPENSSH_FINGERPRINT");

    insertNewAuth.setBigDecimal(1, sessionId);
    insertNewAuth.setObject(2, timestamp);
    insertNewAuth.setString(3, event);
    insertNewAuth.setString(4, username);
    insertNewAuth.setString(5, hashAlgo);
    insertNewAuth.setString(6, fingerprint);
    insertNewAuth.executeUpdate();
  }
}
