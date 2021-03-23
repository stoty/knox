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
package org.apache.knox.gateway.services.token.impl;

import static org.apache.knox.gateway.config.GatewayConfig.REMOTE_CONFIG_REGISTRY_ADDRESS;
import static org.apache.knox.gateway.config.GatewayConfig.REMOTE_CONFIG_REGISTRY_TYPE;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.curator.test.InstanceSpec;
import org.apache.curator.test.TestingCluster;
import org.apache.curator.test.TestingZooKeeperServer;
import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.service.config.remote.zk.ZooKeeperClientService;
import org.apache.knox.gateway.service.config.remote.zk.ZooKeeperClientServiceProvider;
import org.apache.knox.gateway.services.GatewayServices;
import org.apache.knox.gateway.services.ServiceLifecycleException;
import org.apache.knox.gateway.services.ServiceType;
import org.apache.knox.gateway.services.config.client.RemoteConfigurationRegistryClientService;
import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.KeystoreService;
import org.apache.knox.gateway.services.security.KeystoreServiceException;
import org.apache.knox.gateway.services.security.MasterService;
import org.apache.knox.gateway.services.security.token.TokenMetadata;
import org.easymock.EasyMock;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class ZookeeperTokenStateServiceTest {

  @ClassRule
  public static final TemporaryFolder testFolder = new TemporaryFolder();

  private static final String CONFIG_MONITOR_NAME = "remoteConfigMonitorClient";
  private static final long SHORT_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL = 2L;
  private static final long LONG_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL = 5L;
  private static TestingCluster zkNodes;

  @BeforeClass
  public static void configureAndStartZKCluster() throws Exception {
    // Configure security for the ZK cluster instances
    final Map<String, Object> customInstanceSpecProps = new HashMap<>();
    customInstanceSpecProps.put("authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider");
    customInstanceSpecProps.put("requireClientAuthScheme", "sasl");
    customInstanceSpecProps.put("admin.enableServer", false);

    // Define the test cluster (with 2 nodes)
    List<InstanceSpec> instanceSpecs = new ArrayList<>();
    for (int i = 0; i < 2; i++) {
      InstanceSpec is = new InstanceSpec(null, -1, -1, -1, false, (i + 1), -1, -1, customInstanceSpecProps);
      instanceSpecs.add(is);
    }
    zkNodes = new TestingCluster(instanceSpecs);

    // Start the cluster
    zkNodes.start();
  }

  @AfterClass
  public static void tearDownSuite() throws Exception {
    // Shutdown the ZK cluster
    zkNodes.close();
  }

  @Test
  public void testStoringTokenAliasesInZookeeper() throws Exception {
    final ZookeeperTokenStateService zktokenStateService = setupZkTokenStateService(SHORT_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL);

    assertFalse(zkNodeExists("/knox/security/topology/__gateway/tokens/a0/a0-token1"));
    assertFalse(zkNodeExists("/knox/security/topology/__gateway/tokens/a0/a0-token1--max"));

    zktokenStateService.addToken("a0-token1", 1L, 2L);

    // give some time for the token state service to persist the token aliases in ZK (doubled the persistence interval)
    Thread.sleep(2 * SHORT_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL * 1000);

    assertTrue(zkNodeExists("/knox/security/topology/__gateway/tokens/a0/a0-token1"));
    assertTrue(zkNodeExists("/knox/security/topology/__gateway/tokens/a0/a0-token1--max"));
    assertTrue(zktokenStateService.getTokenIds().contains("a0-token1"));
    assertFalse(zktokenStateService.getTokenIds().contains("a0-token1--max"));

    assertFalse(zkNodeExists("/knox/security/topology/__gateway/tokens/a0/a0-token1--unused"));
    zktokenStateService.markTokenUnused("a0-token1");
    Thread.sleep(2 * SHORT_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL * 1000);
    assertTrue(zkNodeExists("/knox/security/topology/__gateway/tokens/a0/a0-token1--unused"));
    assertFalse(zktokenStateService.getTokenIds().contains("a0-token1--unused"));
  }

  @Test
  public void testRetry() throws Exception {
    final ZookeeperTokenStateService zktokenStateServiceNode1 = setupZkTokenStateService(LONG_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL);
    final ZookeeperTokenStateService zktokenStateServiceNode2 = setupZkTokenStateService(LONG_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL);
    zktokenStateServiceNode1.addToken("node1Token", 10L, 2000L);
    final long expiration = zktokenStateServiceNode2.getTokenExpiration("node1Token");
    Thread.sleep(LONG_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL * 1000);
    assertEquals(2000L, expiration);

    final String userName = "testUser";
    final String comment = "This is my test comment";
    zktokenStateServiceNode1.addMetadata("node1Token", new TokenMetadata(userName, comment));
    Thread.sleep(LONG_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL * 1000);
    assertEquals(userName, zktokenStateServiceNode2.getTokenMetadata("node1Token").getUserName());
    assertEquals(comment, zktokenStateServiceNode2.getTokenMetadata("node1Token").getComment());
  }

  @Test
  public void testRenewal() throws Exception {
    final ZookeeperTokenStateService zktokenStateServiceNode1 = setupZkTokenStateService(SHORT_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL);
    final ZookeeperTokenStateService zktokenStateServiceNode2 = setupZkTokenStateService(SHORT_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL);
    final String tokenId = "a1-token";
    final long issueTime = System.currentTimeMillis();
    final long tokenTTL = 1000L;
    final long renewInterval = 2000L;

    zktokenStateServiceNode1.addToken(tokenId, issueTime, issueTime + tokenTTL);
    Thread.sleep(SHORT_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL * 1500);
    assertEquals(zktokenStateServiceNode1.getTokenExpiration(tokenId), zktokenStateServiceNode2.getTokenExpiration(tokenId));

    //now renew token on node 1 and check if renewal is reflected on node2
    zktokenStateServiceNode1.renewToken(tokenId, renewInterval);
    Thread.sleep(SHORT_TOKEN_STATE_ALIAS_PERSISTENCE_INTERVAL * 1500);
    assertEquals(zktokenStateServiceNode1.getTokenExpiration(tokenId), zktokenStateServiceNode2.getTokenExpiration(tokenId));
  }

  private ZookeeperTokenStateService setupZkTokenStateService(long persistenceInterval) throws IOException, KeystoreServiceException, ServiceLifecycleException {
    // mocking GatewayConfig
    final GatewayConfig gc = EasyMock.createNiceMock(GatewayConfig.class);
    expect(gc.getRemoteRegistryConfigurationNames()).andReturn(Collections.singletonList(CONFIG_MONITOR_NAME)).anyTimes();
    final String registryConfig = REMOTE_CONFIG_REGISTRY_TYPE + "=" + ZooKeeperClientService.TYPE + ";" + REMOTE_CONFIG_REGISTRY_ADDRESS + "=" + zkNodes.getConnectString();
    expect(gc.getRemoteRegistryConfiguration(CONFIG_MONITOR_NAME)).andReturn(registryConfig).anyTimes();
    expect(gc.getRemoteConfigurationMonitorClientName()).andReturn(CONFIG_MONITOR_NAME).anyTimes();
    expect(gc.getAlgorithm()).andReturn("AES").anyTimes();
    expect(gc.isRemoteAliasServiceEnabled()).andReturn(true).anyTimes();
    expect(gc.getKnoxTokenStateAliasPersistenceInterval()).andReturn(persistenceInterval).anyTimes();
    final Path baseFolder = Paths.get(testFolder.newFolder().getAbsolutePath());
    expect(gc.getGatewayDataDir()).andReturn(Paths.get(baseFolder.toString(), "data").toString()).anyTimes();
    expect(gc.getGatewayKeystoreDir()).andReturn(Paths.get(baseFolder.toString(), "data", "keystores").toString()).anyTimes();
    replay(gc);

    // mocking GatewayServices
    final GatewayServices gatewayServices = EasyMock.createNiceMock(GatewayServices.class);
    final char[] masterSecret = "ThisIsMySup3rS3cr3tM4sterPassW0rd!".toCharArray();
    final MasterService masterService = EasyMock.createNiceMock(MasterService.class);
    expect(masterService.getMasterSecret()).andReturn(masterSecret).anyTimes();
    expect(gatewayServices.getService(ServiceType.MASTER_SERVICE)).andReturn(masterService).anyTimes();
    final KeystoreService keystoreservice = EasyMock.createNiceMock(KeystoreService.class);
    expect(keystoreservice.getCredentialStoreForCluster(AliasService.NO_CLUSTER_NAME)).andReturn(null).anyTimes();
    expect(gatewayServices.getService(ServiceType.KEYSTORE_SERVICE)).andReturn(keystoreservice).anyTimes();
    final AliasService aliasService = EasyMock.createNiceMock(AliasService.class);
    expect(gatewayServices.getService(ServiceType.ALIAS_SERVICE)).andReturn(aliasService).anyTimes();
    final RemoteConfigurationRegistryClientService clientService = (new ZooKeeperClientServiceProvider()).newInstance();
    clientService.setAliasService(aliasService);
    clientService.init(gc, Collections.emptyMap());
    expect(gatewayServices.getService(ServiceType.REMOTE_REGISTRY_CLIENT_SERVICE)).andReturn(clientService).anyTimes();
    replay(gatewayServices, masterService, keystoreservice);

    final ZookeeperTokenStateService zktokenStateService = new ZookeeperTokenStateService(gatewayServices);
    zktokenStateService.init(gc, new HashMap<>());
    zktokenStateService.start();
    return zktokenStateService;
  }

  private boolean zkNodeExists(String nodeName) {
    for (TestingZooKeeperServer server : zkNodes.getServers()) {
      if (server.getQuorumPeer().getActiveServer().getZKDatabase().getNode(nodeName) != null) {
        return true;
      }
    }
    return false;
  }
}
