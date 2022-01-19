/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.knox.gateway.cloud.idbroker.google;

import com.google.cloud.hadoop.fs.gcs.GoogleHadoopFileSystemBase;
import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxToken;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxTokenMonitor;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.easymock.EasyMockSupport;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.lang.reflect.Field;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.concurrent.ScheduledExecutorService;

import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.LOCAL_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CAB_TOKEN_KIND;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_TEST_TOKEN_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_ENABLE_TOKEN_MONITOR;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestCABDelegationTokenBindingTest extends EasyMockSupport {

  @Rule
  public final TemporaryFolder testFolder = new TemporaryFolder();

  private static final long EXPIRATION_TIME = System.currentTimeMillis();


  @Test
  public void testPathNotSpecified() throws Exception {

    Configuration configuration = new Configuration();
    assertNull(configuration.get(CONFIG_TEST_TOKEN_PATH));

    AccessTokenProvider.AccessToken realCredentials = new AccessTokenProvider.AccessToken("test_token", EXPIRATION_TIME);

    TestCABDelegationTokenBinding binding = createTestCABDelegationTokenBinding(configuration, realCredentials);

    // expecting the binding to return credentials retrieved from the IDBroker via the IDBClient impl
    GoogleTempCredentials credentials = binding.updateGCPCredentials();
    assertEquals(realCredentials.getToken(), credentials.getToken());
    assertEquals(realCredentials.getExpirationTimeMilliSeconds(), Long.valueOf(credentials.getExpiration()));

    AccessTokenProvider.AccessToken accessToken = credentials.toAccessToken();
    assertEquals(realCredentials.getToken(), accessToken.getToken());
    assertEquals(realCredentials.getExpirationTimeMilliSeconds(), accessToken.getExpirationTimeMilliSeconds());

    verifyAll();
  }

  @Test
  public void testPathDoesNotExist() throws Exception {
    String invalidPath = testFolder.getRoot().getAbsolutePath() + "/non_existent_file";

    Configuration configuration = new Configuration();
    configuration.set(CONFIG_TEST_TOKEN_PATH, invalidPath);

    assertEquals(invalidPath, configuration.get(CONFIG_TEST_TOKEN_PATH));
    assertFalse(Files.exists(Paths.get(invalidPath)));

    AccessTokenProvider.AccessToken realCredentials = new AccessTokenProvider.AccessToken("test_token", EXPIRATION_TIME);

    TestCABDelegationTokenBinding binding = createTestCABDelegationTokenBinding(configuration, realCredentials);

    // expecting the binding to return credentials retrieved from the IDBroker via the IDBClient impl
    GoogleTempCredentials credentials = binding.updateGCPCredentials();
    assertEquals(realCredentials.getToken(), credentials.getToken());
    assertEquals(realCredentials.getExpirationTimeMilliSeconds(), Long.valueOf(credentials.getExpiration()));

    AccessTokenProvider.AccessToken accessToken = credentials.toAccessToken();
    assertEquals(realCredentials.getToken(), accessToken.getToken());
    assertEquals(realCredentials.getExpirationTimeMilliSeconds(), accessToken.getExpirationTimeMilliSeconds());

    verifyAll();
  }

  @Test
  public void testPathIsNotAFile() throws Exception {
    String directoryPath = testFolder.newFolder().getAbsolutePath();

    Configuration configuration = new Configuration();
    configuration.set(CONFIG_TEST_TOKEN_PATH, directoryPath);

    assertEquals(directoryPath, configuration.get(CONFIG_TEST_TOKEN_PATH));
    assertTrue(Files.isDirectory(Paths.get(directoryPath)));

    AccessTokenProvider.AccessToken realCredentials = new AccessTokenProvider.AccessToken("test_token", EXPIRATION_TIME);

    TestCABDelegationTokenBinding binding = createTestCABDelegationTokenBinding(configuration, realCredentials);

    // expecting the binding to return credentials retrieved from the IDBroker via the IDBClient impl
    GoogleTempCredentials credentials = binding.updateGCPCredentials();
    assertEquals(realCredentials.getToken(), credentials.getToken());
    assertEquals(realCredentials.getExpirationTimeMilliSeconds(), Long.valueOf(credentials.getExpiration()));

    AccessTokenProvider.AccessToken accessToken = credentials.toAccessToken();
    assertEquals(realCredentials.getToken(), accessToken.getToken());
    assertEquals(realCredentials.getExpirationTimeMilliSeconds(), accessToken.getExpirationTimeMilliSeconds());

    verifyAll();
  }

  @Test
  public void testGetExpiredToken() throws Exception {
    String path = getClass().getResource("/expired_access_tokens/gcp.json").getPath();

    Configuration configuration = new Configuration();
    configuration.set(CONFIG_TEST_TOKEN_PATH, path);

    assertEquals(path, configuration.get(CONFIG_TEST_TOKEN_PATH));

    AccessTokenProvider.AccessToken realCredentials = new AccessTokenProvider.AccessToken("test_token", EXPIRATION_TIME);

    TestCABDelegationTokenBinding binding = createTestCABDelegationTokenBinding(configuration, realCredentials);

    // The 1st call to get credentials should return test credentials retrieved from the file system
    GoogleTempCredentials testCredentials = binding.updateGCPCredentials();

    assertNotNull(testCredentials);
    assertEquals("ya29.c.EvYBEQewBHTeQ2pzpfS0jJxq3LRtjcKy-dhMxxIlGUSzkFMBGLektMV_F8HGLkvk5B1Fw045ClJbEtN47kpM-YQtV2Jizct7QfcdTKnJT8apAhZ6TmyGD9tPgiSKnC6ABbweWdbHT8dcNK0cssxr6HIJ9S_1kUkTcmPJpy0YkLyJdM1WNGwq9PBaXalliCvheXmLqiS7iMo6vT4Lns11WOhcP_OQSF3Ord5Qi3gua-9n20cSuOIbykmY79gFl2VxRJF9uPyahJ1XR6_xi1fT8mIGb65fLmbTr5YLWRl3M1GWjexR16XFnH2G0l2U3uftycRfHvLX4egM", testCredentials.getToken());
    // 2019-05-22T19:59:53Z -> 1558555193 (seconds since Epoch)
    assertEquals(Instant.ofEpochSecond(1558555193L), Instant.ofEpochMilli(testCredentials.getExpiration()));

    // The 2nd call to get credentials should return credentials retrieved from the IDBroker via the IDBClient impl
    GoogleTempCredentials credentials = binding.updateGCPCredentials();
    assertEquals(realCredentials.getToken(), credentials.getToken());
    assertEquals(realCredentials.getExpirationTimeMilliSeconds(), Long.valueOf(credentials.getExpiration()));

    AccessTokenProvider.AccessToken accessToken = credentials.toAccessToken();
    assertEquals(realCredentials.getToken(), accessToken.getToken());
    assertEquals(realCredentials.getExpirationTimeMilliSeconds(), accessToken.getExpirationTimeMilliSeconds());

    verifyAll();
  }

  @Test
  public void testKnoxTokenMonitorDisabledByDefault() throws Exception {
    AccessTokenProvider.AccessToken realCredentials =
        new AccessTokenProvider.AccessToken("test_token", EXPIRATION_TIME);
    TestCABDelegationTokenBinding binding =
                    createTestCABDelegationTokenBinding(new Configuration(), realCredentials, false);

    Field knoxTokenMonitorField =
        TestCABDelegationTokenBinding.class.getSuperclass().getDeclaredField("knoxTokenMonitor");
    knoxTokenMonitorField.setAccessible(true);
    KnoxTokenMonitor tokenMonitor = (KnoxTokenMonitor) knoxTokenMonitorField.get(binding);
    assertNull("KnoxTokenMonitor should not have been initialized.", tokenMonitor);

    verifyAll();
  }

  @Test
  public void testKnoxTokenMonitorDisabledExplicitly() throws Exception {
    Configuration config = new Configuration();
    config.set(IDBROKER_ENABLE_TOKEN_MONITOR.getPropertyName(), "false");

    AccessTokenProvider.AccessToken realCredentials =
        new AccessTokenProvider.AccessToken("test_token", EXPIRATION_TIME);
    TestCABDelegationTokenBinding binding =
                    createTestCABDelegationTokenBinding(config, realCredentials, false);

    Field knoxTokenMonitorField =
        TestCABDelegationTokenBinding.class.getSuperclass().getDeclaredField("knoxTokenMonitor");
    knoxTokenMonitorField.setAccessible(true);
    KnoxTokenMonitor tokenMonitor = (KnoxTokenMonitor) knoxTokenMonitorField.get(binding);
    assertNull("KnoxTokenMonitor should not have been initialized.", tokenMonitor);

    verifyAll();
  }

  @Test
  public void testKnoxTokenMonitorDefaultForKerberosClient() throws Exception {
    Configuration conf = new Configuration();
    conf.set(IDBROKER_ENABLE_TOKEN_MONITOR.getPropertyName(), "true");
    doTestKnoxTokenMonitorInit(conf, true, true);
  }

  @Test
  public void testTokenMonitorDisabledByDefault() throws Exception {
    doTestKnoxTokenMonitorInit(new Configuration(), true, false);
  }

  @Test
  public void testKnoxTokenMonitorDefaultForNonKerberosClient() throws Exception {
    doTestKnoxTokenMonitorInit(new Configuration(), false, false);
  }

  @Test
  public void testKnoxTokenMonitorExplicitlyEnabledForKerberosClient() throws Exception {
    Configuration conf = new Configuration();
    conf.set(IDBROKER_ENABLE_TOKEN_MONITOR.getPropertyName(), "true");
    doTestKnoxTokenMonitorInit(conf, true, true);
  }

  @Test
  public void testKnoxTokenMonitorExplicitlyEnabledForNonKerberosClient() throws Exception {
    Configuration conf = new Configuration();
    conf.set(IDBROKER_ENABLE_TOKEN_MONITOR.getPropertyName(), "true");
    doTestKnoxTokenMonitorInit(conf, false, false);
  }

  @Test
  public void testKnoxTokenMonitorExplicitlyDisabledForKerberosClient() throws Exception {
    Configuration config = new Configuration();
    config.set(IDBROKER_ENABLE_TOKEN_MONITOR.getPropertyName(), "false");

    doTestKnoxTokenMonitorInit(config, true, false);
  }

  private void doTestKnoxTokenMonitorInit(final Configuration config,
                                          final Boolean       isKerberosClient,
                                          final Boolean       expectTokenMonitorInit)
      throws Exception {

    AccessTokenProvider.AccessToken realCredentials =
        new AccessTokenProvider.AccessToken("test_token", EXPIRATION_TIME);
    TestCABDelegationTokenBinding binding =
        createTestCABDelegationTokenBinding(config, isKerberosClient, realCredentials, false);

    binding.serviceStart();

    Field knoxTokenMonitorField =
        TestCABDelegationTokenBinding.class.getSuperclass().getDeclaredField("knoxTokenMonitor");
    knoxTokenMonitorField.setAccessible(true);
    KnoxTokenMonitor tokenMonitor = (KnoxTokenMonitor) knoxTokenMonitorField.get(binding);

    binding.serviceStop();

    if (expectTokenMonitorInit) {
      assertNotNull("KnoxTokenMonitor should have been initialized.", tokenMonitor);

      Field monitorExecutorField = tokenMonitor.getClass().getDeclaredField("executor");
      monitorExecutorField.setAccessible(true);
      ScheduledExecutorService executor = (ScheduledExecutorService) monitorExecutorField.get(tokenMonitor);
      assertTrue("KnoxTokenMonitor should have been shutdown.", executor.isShutdown());
    } else {
      assertNull(tokenMonitor);
    }
  }

  private TestCABDelegationTokenBinding createTestCABDelegationTokenBinding(final Configuration configuration,
                                                                            final AccessTokenProvider.AccessToken realCredentials)
                                                                      throws Exception {
    return createTestCABDelegationTokenBinding(configuration, realCredentials, true);
  }


  private TestCABDelegationTokenBinding createTestCABDelegationTokenBinding(final Configuration configuration,
                                                                            final AccessTokenProvider.AccessToken realCredentials,
                                                                            final boolean expectSessionClose)
      throws Exception {
    return createTestCABDelegationTokenBinding(configuration, false, realCredentials, expectSessionClose);
  }

  private TestCABDelegationTokenBinding createTestCABDelegationTokenBinding(final Configuration configuration,
                                                                            final Boolean       isKerberosClient,
                                                                            final AccessTokenProvider.AccessToken realCredentials,
                                                                            final boolean       expectSessionClose)
      throws Exception {

    final long expiryTime = System.currentTimeMillis() + 60_000;
    final AccessTokenProvider.AccessToken google
        = new AccessTokenProvider.AccessToken("google", expiryTime);
    final String origin = "origin";
    final String cert = "ADAWDWDWDWDAWFFWFWQWFQKJLPMNNBJBMNM";

    configuration.set("fs.gs.ext.cab.address", LOCAL_GATEWAY);

    CABGCPTokenIdentifier identifier = new CABGCPTokenIdentifier(
        CAB_TOKEN_KIND,
        new Text("test_user"),
        new Text("test_renewer"),
        new URI("gs://bucket/"),
        "accessToken",
        expiryTime,
        "BEARER",
        LOCAL_GATEWAY,
        cert,
        new GoogleTempCredentials(google),
        origin,
        true);

    GoogleHadoopFileSystemBase fileSystem = createMock(GoogleHadoopFileSystemBase.class);
    expect(fileSystem.getConf()).andReturn(configuration).anyTimes();

    CloudAccessBrokerSession knoxSession = createMock(CloudAccessBrokerSession.class);
    if (expectSessionClose) {
      knoxSession.close();
      expectLastCall().once();
    }

    boolean isTokenMonitorEnabled =
            Boolean.parseBoolean(configuration.get(IDBROKER_ENABLE_TOKEN_MONITOR.getPropertyName(),
                    IDBROKER_ENABLE_TOKEN_MONITOR.getDefaultValue()));

    boolean isPreferKnoxTokenOverKerberosCredentials =
      Boolean.parseBoolean(configuration.get(GoogleIDBProperty.IDBROKER_PREFER_KNOX_TOKEN_OVER_KERBEROS.getPropertyName(),
                                             GoogleIDBProperty.IDBROKER_PREFER_KNOX_TOKEN_OVER_KERBEROS.getDefaultValue()));

    boolean shouldInitKnoxTokenMonitor =
            isKerberosClient && isPreferKnoxTokenOverKerberosCredentials && isTokenMonitorEnabled;

    IDBClient<AccessTokenProvider.AccessToken> client = createMock(IDBClient.class);
    expect(client.fetchCloudCredentials(knoxSession)).andReturn(realCredentials).anyTimes();
    expect(client.createKnoxCABSession(anyObject(KnoxToken.class))).andReturn(knoxSession).anyTimes();
    expect(client.shouldInitKnoxTokenMonitor()).andReturn(shouldInitKnoxTokenMonitor).anyTimes();

    TestCABDelegationTokenBinding binding = createMockBuilder(TestCABDelegationTokenBinding.class)
                                                .addMockedMethod("getConf")
                                                .withConstructor()
                                                .createMock();
    expect(binding.getConf()).andReturn(configuration).anyTimes();

    replayAll();
    binding.setClient(client);

    binding.bindToFileSystem(fileSystem, new Text("Test Service"));
    binding.bindToTokenIdentifier(identifier);

    return binding;
  }
}
