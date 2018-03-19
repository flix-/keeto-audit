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

package io.keeto.audit.util;

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;

import org.syslog_ng.LogDestination;
import org.syslog_ng.LogMessage;

public class KeetoAuditUtil {

  private static final String LOG_PREFIX                      = "[KeetoAudit] ";
  private static final String JDBC_CONNECTION_STRING_TEMPLATE = "jdbc:mariadb://%s:%d/%s?user=%s&password=%s&useServerPrepStmts=true&useLegacyDatetimeCode=false&serverTimezone=UTC";

  public static String getJdbcConnectionStringFromOptions(LogDestination logDestination) {
    String dbAddr = logDestination.getOption("db_addr");
    if (dbAddr == null) {
      throw new IllegalArgumentException("Option db_addr unknown");
    }
    String dbPort = logDestination.getOption("db_port");
    if (dbPort == null) {
      throw new IllegalArgumentException("Option db_port unknown");
    }
    String dbName = logDestination.getOption("db_name");
    if (dbName == null) {
      throw new IllegalArgumentException("Option db_name unknown");
    }
    String dbUsername = logDestination.getOption("db_username");
    if (dbUsername == null) {
      throw new IllegalArgumentException("Option db_username unknown");
    }
    String dbPassword = logDestination.getOption("db_password");
    if (dbPassword == null) {
      throw new IllegalArgumentException("Option db_password unknown");
    }
    return String.format(JDBC_CONNECTION_STRING_TEMPLATE, dbAddr, Integer.parseInt(dbPort), dbName, dbUsername,
        dbPassword);
  }

  public static OffsetDateTime getTimestampFromLogMessage(LogMessage logMessage) {
    if (logMessage == null) {
      throw new IllegalArgumentException("logMessage == null");
    }
    long unixTime = Long.parseLong(logMessage.getValue("UNIXTIME"));
    Instant unixTimeInstant = Instant.ofEpochSecond(unixTime);
    return OffsetDateTime.ofInstant(unixTimeInstant, ZoneId.of("UTC"));
  }

  public static BigDecimal getSessionIdFromDb(Connection dbConnection, LogMessage logMessage) throws SQLException {
    if (dbConnection == null) {
      throw new IllegalArgumentException("dbConnection == null");
    }
    if (logMessage == null) {
      throw new IllegalArgumentException("logMessage == null");
    }
    final String selectMaxSessionIdPs = "SELECT MAX(session_id) AS session_id from openssh_connect WHERE server_addr = ? AND client_addr = ? AND client_port = ?";

    try (PreparedStatement selectMaxSessionId = dbConnection.prepareStatement(selectMaxSessionIdPs)) {
      String serverAddr = logMessage.getValue("HOST");
      String clientAddr = logMessage.getValue("OPENSSH_CLIENT_ADDR");
      int clientPort = Integer.parseInt(logMessage.getValue("OPENSSH_CLIENT_PORT"));
      selectMaxSessionId.setString(1, serverAddr);
      selectMaxSessionId.setString(2, clientAddr);
      selectMaxSessionId.setInt(3, clientPort);
      ResultSet sessionIdResult = selectMaxSessionId.executeQuery();
      sessionIdResult.first(); // MAX() always returns a row (either result or NULL)
      return sessionIdResult.getBigDecimal("session_id");
    }
  }

  public static String getLogPrefix() {
    return LOG_PREFIX;
  }
}
