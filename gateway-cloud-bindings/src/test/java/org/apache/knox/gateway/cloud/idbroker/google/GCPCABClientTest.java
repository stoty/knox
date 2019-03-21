/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.knox.gateway.cloud.idbroker.google;

import org.apache.hadoop.conf.Configuration;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class GCPCABClientTest {

  private final Logger logger = Logger.getLogger("org.apache.knox.gateway.shell");

  private LogHandler logCapture;
  private Level originalLevel;

  @Before
  public void setUp() {
    originalLevel = logger.getLevel();
    logger.setLevel(Level.FINEST);
    logCapture = new LogHandler();
    logger.addHandler(logCapture);
  }

  @After
  public void tearDown() {
    logger.removeHandler(logCapture);
    logger.setLevel(originalLevel);
  }

  @Test
  public void testCreateKerberosDTSessionWithJAASConfOverride() {
    final String testJaasConf = "/etc/gcpcabclienttest-jaas.conf";

    Configuration conf = new Configuration();
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_JAAS_FILE, testJaasConf);

    doInvokeCreateKerberosDTSession(conf);

    assertEquals(3, logCapture.messages.size());
    assertEquals("The specified JAAS configuration does not exist: " + testJaasConf, logCapture.messages.get(0));
    assertEquals("Using default JAAS configuration", logCapture.messages.get(1));
  }


  @Test
  public void testCreateKerberosDTSessionWithDefaultJAASConf() {
    // Test without the JAAS conf property set
    doInvokeCreateKerberosDTSession(new Configuration());

    assertEquals(2, logCapture.messages.size());
    assertEquals("Using default JAAS configuration", logCapture.messages.get(0));
  }



  private void doInvokeCreateKerberosDTSession(final Configuration conf) {
    try {
      (new GCPCABClient()).createKerberosDTSession(conf, "https://localhost:8443/gateway/dt", null);
    } catch (URISyntaxException e) {
      fail(e.getMessage());
    }
  }


  private static class LogHandler extends Handler {
    final List<String> messages = new ArrayList<>();

    @Override
    public void publish(LogRecord record) {
      messages.add(record.getMessage());
    }

    @Override
    public void flush() {
    }

    @Override
    public void close() throws SecurityException {
    }
  }

}
