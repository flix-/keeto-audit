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

package io.keeto.audit;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.syslog_ng.InternalMessageSender;
import org.syslog_ng.LogMessage;
import org.syslog_ng.StructuredLogDestination;

import io.keeto.audit.event.EventWriter;
import io.keeto.audit.event.EventWriterFactory;
import io.keeto.audit.util.KeetoAuditUtil;

public class SyslogNgMariaDbDestination extends StructuredLogDestination {

  private final String LOG_PREFIX = KeetoAuditUtil.getLogPrefix();

  private String       jdbcConnectionString;
  private Connection   dbConnection;

  public SyslogNgMariaDbDestination(long arg0) {
    super(arg0);
    InternalMessageSender.debug(LOG_PREFIX + "constructor()");
  }

  @Override
  protected boolean init() {
    InternalMessageSender.debug(LOG_PREFIX + "init()");
    jdbcConnectionString = KeetoAuditUtil.getJdbcConnectionStringFromOptions(this);
    InternalMessageSender.debug(LOG_PREFIX + "jdbcConnectionString: " + jdbcConnectionString);
    return true;
  }

  @Override
  protected String getNameByUniqOptions() {
    InternalMessageSender.debug(LOG_PREFIX + "getNameByUniqOptions()");
    String uniqueDiskBufferName = new StringBuilder().append(getClass().getSimpleName()).append("_")
        .append(getOption("db_addr")).append("_").append(getOption("db_port")).append("_").append(getOption("db_name"))
        .toString();
    InternalMessageSender.debug(LOG_PREFIX + "Unique disk buffer name: " + uniqueDiskBufferName);
    return uniqueDiskBufferName;
  }

  @Override
  protected boolean isOpened() {
    InternalMessageSender.debug(LOG_PREFIX + "isOpened()");
    if (dbConnection == null) {
      return false;
    }
    boolean isOpened = false;
    try {
      isOpened = dbConnection.isValid(30);
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
      dbConnection = DriverManager.getConnection(jdbcConnectionString);
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
    EventWriter eventWriter = EventWriterFactory.getEventWriter(event, dbConnection);
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
      if (dbConnection != null && !dbConnection.isClosed()) {
        dbConnection.close();
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
