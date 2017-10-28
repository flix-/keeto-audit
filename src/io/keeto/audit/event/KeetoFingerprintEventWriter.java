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

import org.syslog_ng.LogMessage;

public class KeetoFingerprintEventWriter implements EventWriter {

	private final String insertNewFingerprintPs = "INSERT INTO keeto_fingerprint VALUES (?, ?, ?)";

	private Connection conn;
	
	public KeetoFingerprintEventWriter(Connection conn) {
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
		PreparedStatement insertNewFingerprint = conn.prepareStatement(insertNewFingerprintPs);

		String username = logMessage.getValue("OPENSSH_USERNAME");
		String hashAlgo = logMessage.getValue("OPENSSH_HASH_ALGO");
		String fingerprint = logMessage.getValue("OPENSSH_FINGERPRINT");

		insertNewFingerprint.setString(1, username);
		insertNewFingerprint.setString(2, hashAlgo);
		insertNewFingerprint.setString(3, fingerprint);
		insertNewFingerprint.executeUpdate();
	}
}
