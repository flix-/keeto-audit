/*
 * Copyright (C) 2017-2018 Sebastian Roland <seroland86@gmail.com>
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

import org.syslog_ng.InternalMessageSender;
import org.syslog_ng.LogMessage;

import io.keeto.audit.util.KeetoAuditUtil;

public class OpenSSHAuthEventWriter implements EventWriter {

  private final String     LOG_PREFIX      = KeetoAuditUtil.getLogPrefix();

  private final String     insertNewAuthPs = "INSERT INTO openssh_auth VALUES (?, NULL, ?, ?, ?, ?, ?)";
  private final Connection dbConnection;

  public OpenSSHAuthEventWriter(Connection dbConnection) {
    super();
    if (dbConnection == null) {
      throw new IllegalArgumentException("dbConnection == null");
    }
    this.dbConnection = dbConnection;
  }

  @Override
  public void write(LogMessage logMessage) throws SQLException {
    if (logMessage == null) {
      throw new IllegalArgumentException("logMessage == null");
    }
    BigDecimal sessionId = KeetoAuditUtil.getSessionIdFromDb(dbConnection, logMessage);
    if (sessionId == null) {
      throw new IllegalStateException("Session id not found");
    }
    OffsetDateTime timestamp = KeetoAuditUtil.getTimestampFromLogMessage(logMessage);
    String event = logMessage.getValue("KEETO_AUDIT_EVENT");
    String username = logMessage.getValue("OPENSSH_USERNAME");
    String hashAlgo = logMessage.getValue("OPENSSH_HASH_ALGO");
    String fingerprint = logMessage.getValue("OPENSSH_FINGERPRINT");

    try (PreparedStatement insertNewAuth = dbConnection.prepareStatement(insertNewAuthPs)) {
      insertNewAuth.setBigDecimal(1, sessionId);
      insertNewAuth.setObject(2, timestamp);
      insertNewAuth.setString(3, event);
      insertNewAuth.setString(4, username);
      insertNewAuth.setString(5, hashAlgo);
      insertNewAuth.setString(6, fingerprint);

      int insertCount = insertNewAuth.executeUpdate();
      switch (insertCount) {
      case 1:
        InternalMessageSender.debug(LOG_PREFIX + "Added new authentication event");
        break;
      default:
        InternalMessageSender.debug(LOG_PREFIX + "Failed to add authentication event");
      }
    }
  }
}
