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

import org.syslog_ng.InternalMessageSender;

import io.keeto.audit.util.KeetoAuditUtil;

public class EventWriterFactory {

  private static final String LOG_PREFIX = KeetoAuditUtil.getLogPrefix();

  public static EventWriter getEventWriter(String event, Connection dbConnection) {
    if (event == null) {
      throw new IllegalArgumentException("event == null");
    }
    if (dbConnection == null) {
      throw new IllegalArgumentException("dbConnection == null");
    }
    switch (event) {
    case "OPENSSH_CONNECT":
      return new OpenSSHConnectEventWriter(dbConnection);
    case "KEETO_FINGERPRINT":
      return new KeetoFingerprintEventWriter(dbConnection);
    case "OPENSSH_AUTH_FAILURE":
    case "OPENSSH_AUTH_SUCCESS":
      return new OpenSSHAuthEventWriter(dbConnection);
    case "OPENSSH_DISCONNECT":
      return new OpenSSHDisconnectEventWriter(dbConnection);
    default:
      InternalMessageSender.warning(LOG_PREFIX + "Received unknown event: " + event);
      return new UnknownEventWriter(dbConnection);
    }
  }
}
