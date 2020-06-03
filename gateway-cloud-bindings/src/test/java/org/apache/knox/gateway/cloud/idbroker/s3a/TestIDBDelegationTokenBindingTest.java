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
package org.apache.knox.gateway.cloud.idbroker.s3a;

import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.LOCAL_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.s3a.IDBS3AConstants.IDB_TOKEN_KIND;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_TEST_TOKEN_PATH;
import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.delegation.EncryptionSecrets;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.UserGroupInformation;
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

public class TestIDBDelegationTokenBindingTest extends EasyMockSupport {

  @Rule
  public final TemporaryFolder testFolder = new TemporaryFolder();

  @Test
  public void testPathNotSpecified() throws Exception {
    Configuration configuration = new Configuration();
    configuration.set(IDBROKER_GATEWAY.getPropertyName(), IDBROKER_GATEWAY.getDefaultValue());
    assertNull(configuration.get(IDBROKER_TEST_TOKEN_PATH.getPropertyName()));

    MarshalledCredentials realCredentials = MarshalledCredentials.empty();

    CloudAccessBrokerSession mockKnoxSession = createMock(CloudAccessBrokerSession.class);

    S3AIDBClient mockClient = createMock(S3AIDBClient.class);
    expect(mockClient.fetchCloudCredentials(mockKnoxSession)).andReturn(realCredentials).anyTimes();

    TestIDBDelegationTokenBinding binding = createTestIDBDelegationTokenBinding(configuration, realCredentials);

    // expecting the binding to return credentials retrieved from the IDBroker via the IDBClient impl
    assertSame(realCredentials, binding.fetchMarshalledAWSCredentials(mockClient, mockKnoxSession));

    verifyAll();
  }

  @Test
  public void testPathDoesNotExist() throws Exception {
    String invalidPath = testFolder.getRoot().getAbsolutePath() + "/non_existent_file";

    Configuration configuration = new Configuration();
    configuration.set(IDBROKER_TEST_TOKEN_PATH.getPropertyName(), invalidPath);

    assertEquals(invalidPath, configuration.get(IDBROKER_TEST_TOKEN_PATH.getPropertyName()));
    assertFalse(Files.exists(Paths.get(invalidPath)));

    MarshalledCredentials realCredentials = MarshalledCredentials.empty();

    CloudAccessBrokerSession mockKnoxSession = createMock(CloudAccessBrokerSession.class);

    S3AIDBClient mockClient = createMock(S3AIDBClient.class);
    expect(mockClient.fetchCloudCredentials(mockKnoxSession)).andReturn(realCredentials).anyTimes();

    TestIDBDelegationTokenBinding binding = createTestIDBDelegationTokenBinding(configuration, realCredentials);

    // expecting the binding to return credentials retrieved from the IDBroker via the IDBClient impl
    assertSame(realCredentials, binding.fetchMarshalledAWSCredentials(mockClient, mockKnoxSession));

    verifyAll();
  }

  @Test
  public void testPathIsNotAFile() throws Exception {
    String directoryPath = testFolder.newFolder().getAbsolutePath();

    Configuration configuration = new Configuration();
    configuration.set(IDBROKER_TEST_TOKEN_PATH.getPropertyName(), directoryPath);

    assertEquals(directoryPath, configuration.get(IDBROKER_TEST_TOKEN_PATH.getPropertyName()));
    assertTrue(Files.isDirectory(Paths.get(directoryPath)));

    MarshalledCredentials realCredentials = MarshalledCredentials.empty();

    CloudAccessBrokerSession mockKnoxSession = createMock(CloudAccessBrokerSession.class);

    S3AIDBClient mockClient = createMock(S3AIDBClient.class);
    expect(mockClient.fetchCloudCredentials(mockKnoxSession)).andReturn(realCredentials).anyTimes();

    TestIDBDelegationTokenBinding binding = createTestIDBDelegationTokenBinding(configuration, realCredentials);

    // expecting the binding to return credentials retrieved from the IDBroker via the IDBClient impl
    assertSame(realCredentials, binding.fetchMarshalledAWSCredentials(mockClient, mockKnoxSession));

    verifyAll();
  }

  @Test
  public void testGetExpiredToken() throws Exception {
    String path = getClass().getResource("/expired_access_tokens/aws.json").getPath();

    Configuration configuration = new Configuration();
    configuration.set(IDBROKER_GATEWAY.getPropertyName(), LOCAL_GATEWAY);
    configuration.set(IDBROKER_TEST_TOKEN_PATH.getPropertyName(), path);

    assertEquals(path, configuration.get(IDBROKER_TEST_TOKEN_PATH.getPropertyName()));

    MarshalledCredentials realCredentials = MarshalledCredentials.empty();

    CloudAccessBrokerSession mockKnoxSession = createMock(CloudAccessBrokerSession.class);

    S3AIDBClient mockClient = createMockBuilder(S3AIDBClient.class)
                                .addMockedMethod(S3AIDBClient.class.getMethod("fetchCloudCredentials",
                                                                              CloudAccessBrokerSession.class))
                                .addMockedMethod(S3AIDBClient.class.getMethod("getGatewayAddress"))
                                .addMockedMethod(S3AIDBClient.class.getMethod("toString"))
                                .createMock();
    expect(mockClient.fetchCloudCredentials(mockKnoxSession)).andReturn(realCredentials);
    expect(mockClient.getGatewayAddress()).andReturn(LOCAL_GATEWAY);

    TestIDBDelegationTokenBinding binding = createTestIDBDelegationTokenBinding(configuration, realCredentials);

    // The 1st call to get credentials should return test credentials retrieved from the file system
    MarshalledCredentials testCredentials = binding.fetchMarshalledAWSCredentials(mockClient, mockKnoxSession);

    assertNotNull(testCredentials);
    assertEquals("FQoGZXIvYXdzEN///////////wEaDDzvt4caYCkHAj6EmCL9AcNScwUWFWfsnl5s1eiUniy/qScX+EdOPkJaNr7rT/vk/uEFOWIVfU4SzQCm2tHkYMBvVZb6W9FOs03yjdVy03NFnS/3z3zvXkT/sqFGY9RGHbdGLapJvS2oWXB1Itr2lFexuqVfrDAGfOk4b0TQv+pWRLKuJ02qohuz3YmhaDDTT96+y8gQkqo+/BdzdkNXsgSdSobBQpsSbvOQcaCoFdnuhopjSh5FuQ4TLvFnJ2RYfl23wJg9XWrr0U94izQ/gkmN5wxzTZ6/8RrCSB70YY50AblU3n9fvWD331/Y4gqkgST5ZWjn98yPF635qFXoWRrNu3haeeNxPELtMIEojfKf5wU=", testCredentials.getSessionToken());
    assertEquals(Instant.ofEpochSecond(1558710045000L), Instant.ofEpochSecond(testCredentials.getExpiration()));

    // The 2nd call to get credentials should return credentials retrieved from the IDBroker via the IDBClient impl
    assertSame(realCredentials, binding.fetchMarshalledAWSCredentials(mockClient, mockKnoxSession));

    verifyAll();
  }

  @Test
  public void testKnoxTokenMonitorEnabledByDefault() throws Exception {
    UserGroupInformation mockOwner = createNiceMock(UserGroupInformation.class);
    expect(mockOwner.hasKerberosCredentials()).andReturn(true).anyTimes();
    doTestKnoxTokenMonitorEnabled(new Configuration(), mockOwner);
  }

  @Test
  public void testKnoxTokenMonitorEnabled() throws Exception {
    Configuration config = new Configuration();
    config.set(S3AIDBProperty.IDBROKER_ENABLE_TOKEN_MONITOR.getPropertyName(), "true");

    UserGroupInformation mockOwner = createNiceMock(UserGroupInformation.class);
    expect(mockOwner.hasKerberosCredentials()).andReturn(true).anyTimes();

    doTestKnoxTokenMonitorEnabled(config, mockOwner);
  }

  @Test
  public void testKnoxTokenMonitorEnabledButNoKerberos() throws Exception {
    Configuration config = new Configuration();
    config.set(S3AIDBProperty.IDBROKER_ENABLE_TOKEN_MONITOR.getPropertyName(), "true");

    // Even though the configuration enabled the token monitor, the lack of Kerberos credentials should disable it
    UserGroupInformation mockOwner = createNiceMock(UserGroupInformation.class);
    expect(mockOwner.hasKerberosCredentials()).andReturn(false).anyTimes();

    doTestKnoxTokenMonitorDisabled(config, mockOwner);
  }

  @Test
  public void testKnoxTokenMonitorDisabledExplicitly() throws Exception {
    Configuration config = new Configuration();
    config.set(S3AIDBProperty.IDBROKER_ENABLE_TOKEN_MONITOR.getPropertyName(), "false");

    // Even though the owner has Kerberos credentials, the explicit config should disable the token monitor
    UserGroupInformation mockOwner = createNiceMock(UserGroupInformation.class);
    expect(mockOwner.hasKerberosCredentials()).andReturn(true).anyTimes();

    doTestKnoxTokenMonitorDisabled(config, mockOwner);
  }

  private void doTestKnoxTokenMonitorEnabled(Configuration config, UserGroupInformation owner) throws Exception {
    MarshalledCredentials realCredentials = MarshalledCredentials.empty();

    TestIDBDelegationTokenBinding binding = createTestIDBDelegationTokenBinding(config, owner, realCredentials);

    Field knoxTokenMonitorField =
        TestIDBDelegationTokenBinding.class.getSuperclass().getDeclaredField("knoxTokenMonitor");
    knoxTokenMonitorField.setAccessible(true);
    KnoxTokenMonitor tokenMonitor = (KnoxTokenMonitor) knoxTokenMonitorField.get(binding);
    assertNotNull("KnoxTokenMonitor should have been initialized.", tokenMonitor);

    // Stop the KnoxTokenMonitor
    binding.stop();

    // Verify the token monitor was shutdown
    Field monitorExecutorField = tokenMonitor.getClass().getDeclaredField("executor");
    monitorExecutorField.setAccessible(true);
    ScheduledExecutorService executor = (ScheduledExecutorService) monitorExecutorField.get(tokenMonitor);
    assertTrue("KnoxTokenMonitor should have been shutdown.", executor.isShutdown());

    verifyAll();
  }

  private void doTestKnoxTokenMonitorDisabled(Configuration config, UserGroupInformation owner) throws Exception {
    MarshalledCredentials realCredentials = MarshalledCredentials.empty();
    TestIDBDelegationTokenBinding binding = createTestIDBDelegationTokenBinding(config, owner, realCredentials);

    Field knoxTokenMonitorField =
        TestIDBDelegationTokenBinding.class.getSuperclass().getDeclaredField("knoxTokenMonitor");
    knoxTokenMonitorField.setAccessible(true);
    KnoxTokenMonitor tokenMonitor = (KnoxTokenMonitor) knoxTokenMonitorField.get(binding);
    assertNull("KnoxTokenMonitor should not have been initialized.", tokenMonitor);

    // Verify that the missing KnoxTokenMonitor does not cause stop to fail
    binding.stop();

    verifyAll();
  }


  @SuppressWarnings("unused")
  private TestIDBDelegationTokenBinding createTestIDBDelegationTokenBinding(Configuration         configuration,
                                                                            MarshalledCredentials realCredentials)
      throws Exception {
    UserGroupInformation mockOwner = createMock(UserGroupInformation.class);
    expect(mockOwner.hasKerberosCredentials()).andReturn(false).anyTimes();
    return createTestIDBDelegationTokenBinding(configuration, mockOwner, realCredentials);
  }

  @SuppressWarnings("unused")
  private TestIDBDelegationTokenBinding createTestIDBDelegationTokenBinding(Configuration         configuration,
                                                                            UserGroupInformation  owner,
                                                                            MarshalledCredentials realCredentials)
      throws Exception {

    URI bogusUri = new URI("s3a://bogus");

    S3AFileSystem mockS3AFileSystem = createMock(S3AFileSystem.class);
    expect(mockS3AFileSystem.getOwner()).andReturn(owner).anyTimes();
    expect(mockS3AFileSystem.getBucket()).andReturn(null).anyTimes();

    EncryptionSecrets mockEncryptionSecrets = createMock(EncryptionSecrets.class);

    IDBS3ATokenIdentifier identifier = new IDBS3ATokenIdentifier(
        IDB_TOKEN_KIND,
        new Text("test_user"),
        null,
        bogusUri,
        "...",
        System.currentTimeMillis(),
        MarshalledCredentials.empty(),
        mockEncryptionSecrets,
        "testing",
        "test case",
        System.currentTimeMillis(),
        "correlation id",
        LOCAL_GATEWAY,
        "BOGUS.......");

    replayAll();

    TestIDBDelegationTokenBinding binding = new TestIDBDelegationTokenBinding();
    binding.bindToFileSystem(bogusUri, mockS3AFileSystem);
    binding.init(configuration);
    binding.bindToTokenIdentifier(identifier);

    return binding;
  }
}
