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

public class EventWriterFactory {

  public static EventWriter getEventWriter(String event, Connection conn) {
    if (conn == null) {
      throw new IllegalArgumentException("conn == null");
    }
    switch (event) {
    case "OPENSSH_CONNECT":
      return new OpenSSHConnectEventWriter(conn);
    case "KEETO_FINGERPRINT":
      return new KeetoFingerprintEventWriter(conn);
    case "OPENSSH_AUTH_FAILURE":
    case "OPENSSH_AUTH_SUCCESS":
      return new OpenSSHAuthEventWriter(conn);
    case "OPENSSH_DISCONNECT":
      return new OpenSSHDisconnectEventWriter(conn);
    default:
      throw new IllegalArgumentException(event);
    }
  }
}
