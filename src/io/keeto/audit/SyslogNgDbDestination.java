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

package io.keeto.audit;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.syslog_ng.InternalMessageSender;
import org.syslog_ng.LogMessage;
import org.syslog_ng.StructuredLogDestination;

import io.keeto.audit.event.EventWriter;
import io.keeto.audit.event.EventWriterFactory;

public class SyslogNgDbDestination extends StructuredLogDestination {

	private static final String LOG_PREFIX = "KeetoAudit: ";
	private static final String JDBC_CONNECTION_STRING = "jdbc:mariadb://keeto-mariadb:3306/keeto-audit?user=root&password=test123&useServerPrepStmts=true";
	
	private Connection conn;
	
	public SyslogNgDbDestination(long arg0) {
		super(arg0);
		InternalMessageSender.debug(LOG_PREFIX + "constructor()");
	}

	@Override
	protected boolean init() {
		InternalMessageSender.debug(LOG_PREFIX + "init()");
		return true;
	}
	
	@Override
	protected String getNameByUniqOptions() {
		InternalMessageSender.debug(LOG_PREFIX + "getNameByUniqOptions()");
		return "KeetoAudit";
	}

	@Override
	protected boolean isOpened() {
		InternalMessageSender.debug(LOG_PREFIX + "isOpened()");
		if (conn == null) {
			return false;
		}
		boolean isOpened = false;
		try {
			isOpened = conn.isValid(30);
		} catch (SQLException e) {
			InternalMessageSender.debug(LOG_PREFIX + e.getMessage());
			return false;
		}
		return isOpened;
	}

	@Override
	protected boolean open() {
		InternalMessageSender.debug(LOG_PREFIX + "open()");
		try {
			conn = DriverManager.getConnection(JDBC_CONNECTION_STRING);
			return true;
		} catch (SQLException e) {
			InternalMessageSender.debug(LOG_PREFIX + e.getMessage());
			return false;
		}
	}

	@Override
	protected boolean send(LogMessage logMessage) {
		if (logMessage == null) {
			throw new IllegalArgumentException("logMessage == null");
		}
		InternalMessageSender.debug(LOG_PREFIX + "send()");
		String event = logMessage.getValue("KEETO_AUDIT_EVENT");
		EventWriter eventWriter = EventWriterFactory.getEventWriter(event, conn);
		try {
			eventWriter.write(logMessage);
		} catch (SQLException e) {
			InternalMessageSender.debug(LOG_PREFIX + e.getMessage());
			return false;
		}
		return true;
	}

	@Override
	protected void close() {
		InternalMessageSender.debug(LOG_PREFIX + "close()");
		try {
			if (conn != null && !conn.isClosed()) {
				conn.close();
			}
		} catch (SQLException e) {
			InternalMessageSender.debug(LOG_PREFIX + e.getMessage());
		}
	}

	@Override
	protected void deinit() {
		InternalMessageSender.debug(LOG_PREFIX + "deinit()");
	}
}
