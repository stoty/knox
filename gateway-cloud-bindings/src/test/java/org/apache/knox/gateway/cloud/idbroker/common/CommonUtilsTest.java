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
package org.apache.knox.gateway.cloud.idbroker.common;

import org.apache.hadoop.conf.Configuration;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;


public class CommonUtilsTest {

  @Test
  public void testAddSSLClientConfigurationResourceMultipleTimes() {
    final String resource = "test-conf-res.xml";

    Configuration conf = new Configuration();
    conf.set(CommonConstants.SSL_CLIENT_CONF, resource);

    // The referenced resource's properties should not be available at this point
    assertNull(conf.get("ssl.client.truststore.location"));
    assertNull(conf.get("ssl.client.truststore.password"));
    assertNull(conf.get("ssl.client.truststore.type"));
    assertNull(conf.get("ssl.client.truststore.reload.interval"));

    // Ensure the SSL client config resource is added to the configuration
    CommonUtils.ensureSSLClientConfigLoaded(conf);

    // Validate the referenced resource's properties
    assertNotNull(conf.get("ssl.client.truststore.location"));
    final String location = conf.get("ssl.client.truststore.location");
    assertNotNull(conf.get("ssl.client.truststore.password"));
    final String pass = conf.get("ssl.client.truststore.password");
    assertNotNull(conf.get("ssl.client.truststore.type"));
    final String type = conf.get("ssl.client.truststore.type");
    assertNotNull(conf.get("ssl.client.truststore.reload.interval"));
    final String interval = conf.get("ssl.client.truststore.reload.interval");

    // Re-ensure the SSL client config resource is added to the configuration
    CommonUtils.ensureSSLClientConfigLoaded(conf);

    // Make sure the properties are still available from the configuration, and that they have the same values
    assertEquals(location, conf.get("ssl.client.truststore.location"));
    assertEquals(pass, conf.get("ssl.client.truststore.password"));
    assertEquals(type, conf.get("ssl.client.truststore.type"));
    assertEquals(interval, conf.get("ssl.client.truststore.reload.interval"));
  }

}
