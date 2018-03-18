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

import org.syslog_ng.InternalMessageSender;
import org.syslog_ng.LogMessage;

import io.keeto.audit.util.KeetoAuditUtil;

public class KeetoFingerprintEventWriter implements EventWriter {

  private final String     LOG_PREFIX                       = KeetoAuditUtil.getLogPrefix();

  private final String     insertFingerprintIfNotExistentPs = "INSERT INTO keeto_fingerprint SELECT * FROM (SELECT ? AS username, ? AS hash_algo, ? AS fingerprint) AS new_row WHERE NOT EXISTS (SELECT * FROM keeto_fingerprint WHERE username = ? AND hash_algo = ? AND fingerprint = ?)";
  private final Connection dbConnection;

  public KeetoFingerprintEventWriter(Connection dbConnection) {
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
    String username = logMessage.getValue("OPENSSH_USERNAME");
    String hashAlgo = logMessage.getValue("OPENSSH_HASH_ALGO");
    String fingerprint = logMessage.getValue("OPENSSH_FINGERPRINT");

    try (PreparedStatement insertFingerprintIfNotExistent = dbConnection
        .prepareStatement(insertFingerprintIfNotExistentPs)) {
      insertFingerprintIfNotExistent.setString(1, username);
      insertFingerprintIfNotExistent.setString(2, hashAlgo);
      insertFingerprintIfNotExistent.setString(3, fingerprint);
      insertFingerprintIfNotExistent.setString(4, username);
      insertFingerprintIfNotExistent.setString(5, hashAlgo);
      insertFingerprintIfNotExistent.setString(6, fingerprint);

      int insertCount = insertFingerprintIfNotExistent.executeUpdate();
      switch (insertCount) {
      case 0:
        InternalMessageSender.debug(LOG_PREFIX + "Fingerprint already present");
        break;
      default:
        InternalMessageSender.debug(LOG_PREFIX + "Added new fingerprint");
      }
    }
  }
}
