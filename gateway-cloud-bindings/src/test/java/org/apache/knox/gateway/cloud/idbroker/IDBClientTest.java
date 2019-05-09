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
package org.apache.knox.gateway.cloud.idbroker;

import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.cloud.idbroker.common.CommonConstants;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.testng.Assert.assertTrue;

public class IDBClientTest {

  @Test
  public void testS3AConnectorOnlyTrustStoreConfig() throws Exception {
    final File trustStore = createTempTrustStore("my-test-truststore");
    final String pass = "noneofyourbusiness";
    Configuration conf = new Configuration();
    conf.set(IDBConstants.IDBROKER_TRUSTSTORE_LOCATION, trustStore.getAbsolutePath());
    conf.set(IDBConstants.IDBROKER_TRUSTSTORE_PASS, pass);
    try {
      doTestTrustStoreConfig(conf, trustStore.getAbsolutePath(), pass);
    } finally {
      trustStore.delete();
    }
  }

  @Test
  public void testS3AConnectorAndAutoTLSTrustStoreConfig() throws Exception {
    final File trustStore = createTempTrustStore("my-test-truststore");
    final String pass = "noneofyourbusiness";
    Configuration conf = new Configuration();
    conf.set(IDBConstants.IDBROKER_TRUSTSTORE_LOCATION, trustStore.getAbsolutePath());
    conf.set(IDBConstants.IDBROKER_TRUSTSTORE_PASS, pass);
    conf.set(CommonConstants.SSL_TRUSTSTORE_LOCATION, "auto-tls-truststore.jks");
    conf.set(CommonConstants.SSL_TRUSTSTORE_PASS, "auto-tls-truststore-pass");
    try {
      doTestTrustStoreConfig(conf, trustStore.getAbsolutePath(), pass);
    } finally {
      trustStore.delete();
    }
  }

  @Test
  public void testAutoTLSOnlyTrustStoreConfig() throws Exception {
    final File trustStore = createTempTrustStore("auto-tls-truststore");
    final String pass = "auto-tls-truststore-pass";
    Configuration conf = new Configuration();
    conf.set(CommonConstants.SSL_TRUSTSTORE_LOCATION, trustStore.getAbsolutePath());
    conf.set(CommonConstants.SSL_TRUSTSTORE_PASS, pass);
    try {
      doTestTrustStoreConfig(conf, trustStore.getAbsolutePath(), pass);
    } finally {
      trustStore.delete();
    }
  }

  @Test
  public void testUseDTCertConfigDefault() throws Exception {
    final Boolean expectedValue = Boolean.FALSE;
    final Configuration conf = new Configuration();
    doTestUseDTCertConfig(conf, expectedValue);
  }

  @Test
  public void testUseDTCertConfigTrue() throws Exception {
    final Boolean expectedValue = Boolean.TRUE;
    final Configuration conf = new Configuration();
    conf.set(IDBConstants.CAB + CommonConstants.USE_CERT_FROM_DT_SUFFIX, "true");
    doTestUseDTCertConfig(conf, expectedValue);
  }

  @Test
  public void testUseDTCertConfigFalse() throws Exception {
    final Boolean expectedValue = Boolean.FALSE;
    final Configuration conf = new Configuration();
    conf.set(IDBConstants.CAB + CommonConstants.USE_CERT_FROM_DT_SUFFIX, "false");
    doTestUseDTCertConfig(conf, expectedValue);
  }

  private void doTestUseDTCertConfig(final Configuration conf, final Boolean expectedValue)
    throws Exception {
    IDBClient client = IDBClient.createFullIDBClient(conf, null);
    Boolean actualValue = null;
    try {
      Field useIDBCertificateFromDT = IDBClient.class.getDeclaredField("useIDBCertificateFromDT");
      useIDBCertificateFromDT.setAccessible(true);
      actualValue = (Boolean) useIDBCertificateFromDT.get(client);
    } catch (Exception e) {
      fail();
    }
    assertEquals(expectedValue, actualValue);
  }


  private void doTestTrustStoreConfig(Configuration conf, String expectedLocation, String expectedPass)
    throws IOException {
    IDBClient client = IDBClient.createFullIDBClient(conf, null);
    assertEquals(expectedLocation, client.getTruststorePath());
    assertEquals(expectedPass, client.getTruststorePass());
  }

  private File createTempTrustStore(String filename) throws Exception {
    return File.createTempFile(filename, "jks");
  }

}
