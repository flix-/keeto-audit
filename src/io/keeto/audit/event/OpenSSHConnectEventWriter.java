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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.OffsetDateTime;

import org.syslog_ng.InternalMessageSender;
import org.syslog_ng.LogMessage;

import io.keeto.audit.util.KeetoAuditUtil;

public class OpenSSHConnectEventWriter implements EventWriter {

  private final String     LOG_PREFIX         = KeetoAuditUtil.getLogPrefix();

  private final String     insertNewConnectPs = "INSERT INTO openssh_connect VALUES (NULL, ?, ?, ?, ?, ?)";
  private final Connection dbConnection;

  public OpenSSHConnectEventWriter(Connection dbConnection) {
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
    OffsetDateTime timestamp = KeetoAuditUtil.getTimestampFromLogMessage(logMessage);
    String serverAddr = logMessage.getValue("HOST");
    int serverPort = Integer.parseInt(logMessage.getValue("OPENSSH_SERVER_PORT"));
    String clientAddr = logMessage.getValue("OPENSSH_CLIENT_ADDR");
    int clientPort = Integer.parseInt(logMessage.getValue("OPENSSH_CLIENT_PORT"));

    try (PreparedStatement insertNewConnect = dbConnection.prepareStatement(insertNewConnectPs)) {
      insertNewConnect.setObject(1, timestamp);
      insertNewConnect.setString(2, serverAddr);
      insertNewConnect.setInt(3, serverPort);
      insertNewConnect.setString(4, clientAddr);
      insertNewConnect.setInt(5, clientPort);

      int insertCount = insertNewConnect.executeUpdate();
      switch (insertCount) {
      case 1:
        InternalMessageSender.debug(LOG_PREFIX + "Added new connection event");
        break;
      default:
        InternalMessageSender.debug(LOG_PREFIX + "Failed to add connection event");
      }
    }
  }
}
