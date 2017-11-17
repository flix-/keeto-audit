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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.OffsetDateTime;

import org.syslog_ng.LogMessage;

import io.keeto.audit.util.KeetoAuditUtil;

public class OpenSSHConnectEventWriter implements EventWriter {

  private final String insertNewConnectPs = "INSERT INTO openssh_connect VALUES (NULL, ?, ?, ?, ?)";

  private Connection conn;

  public OpenSSHConnectEventWriter(Connection conn) {
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
    PreparedStatement insertNewConnect = conn.prepareStatement(insertNewConnectPs);

    OffsetDateTime timestamp = KeetoAuditUtil.timestampFromLogMessage(logMessage);
    String serverAddr = logMessage.getValue("HOST");
    String clientAddr = logMessage.getValue("OPENSSH_CLIENT_ADDR");
    int clientPort = Integer.parseInt(logMessage.getValue("OPENSSH_CLIENT_PORT"));

    insertNewConnect.setObject(1, timestamp);
    insertNewConnect.setString(2, serverAddr);
    insertNewConnect.setString(3, clientAddr);
    insertNewConnect.setInt(4, clientPort);
    insertNewConnect.executeUpdate();
  }
}
