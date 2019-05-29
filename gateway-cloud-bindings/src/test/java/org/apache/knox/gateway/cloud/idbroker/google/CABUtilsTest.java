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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.IDBTestUtils;

import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.knox.gateway.cloud.idbroker.common.CloudAccessBrokerClient;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;
import org.junit.Test;

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CAB_TOKEN_KIND;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CABUtilsTest {

  @Test
  public void testGetTrustStoreLocation() {
    final String trustStoreLoc = "/some/path/to/my/trust/store";

    Configuration config = new Configuration();
    config.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_LOCATION, trustStoreLoc);
    assertEquals(trustStoreLoc, CABUtils.getTrustStoreLocation(config));

    // Try with extra space in the property value (to validate the use of Configuration#getTrimmed())
    config.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_LOCATION, trustStoreLoc + "   ");
    assertEquals(trustStoreLoc, CABUtils.getTrustStoreLocation(config));
  }

//  @Test
//  public void testGetCloudAccessBrokerAddress() {
//    final String address = "http://host1:8444/gateway";
//    doTestGetCloudAccessBrokerAddress(address, address);
//  }
//
//  @Test
//  public void testGetCloudAccessBrokerAddressMultiValue() {
//    final String address = "http://host1:8444/gateway,http://host2:8444/gateway, http://host3:8444/gateway";
//    doTestGetCloudAccessBrokerAddress(address.split(", *")[0], address);
//  }

  @Test
  public void testGetCloudAccessBrokerAddresses() {
    final String[] addresses = {"http://host1:8444/gateway"};
    doTestGetCloudAccessBrokerAddresses(addresses, addresses);
  }

  @Test
  public void testGetCloudAccessBrokerAddressesMultiValue() {
    final String[] addresses = {"http://host1:8444/gateway/", "http://host2:8444/gateway", "http://host3:8444/gateway/"};
    doTestGetCloudAccessBrokerAddresses(addresses, addresses);
  }

//  private void doTestGetCloudAccessBrokerAddress(final String expectedAddress, final String address) {
//    Configuration config = new Configuration();
//    config.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS, address);
//    validateURL(expectedAddress, CABUtils.getCloudAccessBrokerAddress(config));
//  }

  private void doTestGetCloudAccessBrokerAddresses(final String[] expectedAddresses, final String...addresses) {
    Configuration config = new Configuration();
    CABUtils.setCloudAccessBrokerAddresses(config, addresses);
    assertEquals(expectedAddresses.length, addresses.length);
    List<String> actualAddressesList = Arrays.asList(addresses);
    for (String expected : expectedAddresses) {
      assertTrue(actualAddressesList.contains(expected));
    }
  }

  @Test
  public void testGetCloudAccessBrokerURL() {
    final String address = "https://myknoxhost:8443/gateway";
    final String path = "mycabpath";
    doTestGetCloudAccessBrokerURL(address + "/" + path, address, path);
  }

  @Test
  public void testGetCloudAccessBrokerURL_TrailingAddressSlash() {
    final String address = "https://myknoxhost:8443/gateway/";
    final String path = "gcp-cab";
    doTestGetCloudAccessBrokerURL(address + path, address, path);
  }

  @Test
  public void testGetCloudAccessBrokerURL_PrecedingPathSlash() {
    final String address = "https://myknoxhost:8443/gateway";
    final String path = "/mypath";
    doTestGetCloudAccessBrokerURL(address + path, address, path);
  }

  @Test
  public void testGetCloudAccessBrokerURL_TrailingAddressSlashAndPrecedingPathSlash() {
    final String address = "https://myknoxhost:8443/gateway/";
    final String path = "/cab";
    doTestGetCloudAccessBrokerURL(address.substring(0, address.length() - 1) + path, address, path);
  }

  private void doTestGetCloudAccessBrokerURL(final String expectedURL, final String address, final String path) {
    Configuration config = new Configuration();
    config.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS, address);
    config.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_PATH, path);
    validateURL(expectedURL, CABUtils.getCloudAccessBrokerURL(config, address));
  }

  @Test
  public void testGetDelegationTokenProviderURL() {
    final String address = "https://myknoxhost:8443/gateway";
    final String path = "dt";
    doTestGetDelegationTokenProviderURL(address + "/" + path, address, path);
  }

  @Test
  public void testGetDelegationTokenProviderURL_TrailingAddressSlash() {
    final String address = "https://myknoxhost:8443/gateway/";
    final String path = "dt";
    doTestGetDelegationTokenProviderURL(address + path, address, path);
  }

  @Test
  public void testGetDelegationTokenProviderURL_PrecedingPathSlash() {
    final String address = "https://myknoxhost:8443/gateway";
    final String path = "/dt";
    doTestGetDelegationTokenProviderURL(address + path, address, path);
  }

  @Test
  public void testGetDelegationTokenProviderURL_TrailingAddressSlashAndPrecedingPathSlash() {
    final String address = "https://myknoxhost:8443/gateway/";
    final String path = "/dt";
    doTestGetDelegationTokenProviderURL(address.substring(0, address.length() - 1) + path, address, path);
  }

  private void doTestGetDelegationTokenProviderURL(final String expectedURL, final String address, final String path) {
    Configuration config = new Configuration();
    config.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS, address);
    config.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_DT_PATH, path);
    validateURL(expectedURL, CABUtils.getDelegationTokenProviderURL(config, address));
  }


  private void validateURL(final String expected, String url) {
    assertNotNull(expected);
    assertFalse(expected.isEmpty());
    assertEquals(expected, url);
  }

  @Test
  public void testRoundTripTokenIdentifier() throws Throwable {
    final long expiryTime = System.currentTimeMillis() + 60_000;
    final AccessTokenProvider.AccessToken google
        = new AccessTokenProvider.AccessToken("google", expiryTime);
    final String origin = "origin";
    final String cert = "ADAWDWDWDWDAWFFWFWQWFQKJLPMNNBJBMNM";

    CABGCPTokenIdentifier identifier = new CABGCPTokenIdentifier(
        CAB_TOKEN_KIND,
        t("owner"),
        new URI("gs://bucket/"),
        "accessToken",
        expiryTime,
        "BEARER",
        "https://gateway:8443/",
        cert,
        new GoogleTempCredentials(google),
        origin);
    CABGCPTokenIdentifier received = IDBTestUtils.roundTrip(identifier, new Configuration());
    assertEquals(identifier, received);
  }

  private Text t(String s) {
    return new Text(s);
  }

  @Test
  public void testGetConfiguredClientDefault() {
    Configuration conf = new Configuration();
    CABUtils.setCloudAccessBrokerAddresses(conf, "https://host1:8444/gateway");
    IDBClient<AccessTokenProvider.AccessToken> client =
        CABUtils.newClient(conf, UserGroupInformation.createUserForTesting("test", new String[]{"test"}));
    assertNotNull(client);
    assertEquals(GoogleIDBClient.class, client.getClass());
  }

  @Test
  public void testGetConfiguredClient() {
    Configuration conf = new Configuration();
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CLIENT_IMPL, TestIDBClient.class.getName());
    IDBClient<AccessTokenProvider.AccessToken> client =
        CABUtils.newClient(conf, UserGroupInformation.createUserForTesting("test", new String[]{"test"}));
    assertNotNull(client);
    assertEquals(TestIDBClient.class, client.getClass());
  }

  @Test
  public void testGetInvalidConfiguredClient() {
    Configuration conf = new Configuration();
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CLIENT_IMPL, TestCloudAccessBrokerClient.class.getName());
    IDBClient<AccessTokenProvider.AccessToken> client =
          CABUtils.newClient(conf, UserGroupInformation.createUserForTesting("test", new String[]{"test"}));
    assertNotNull(client);
    assertEquals("Expected the default client implementation.", GoogleIDBClient.class, client.getClass());
  }


  static class TestIDBClient implements IDBClient<AccessTokenProvider.AccessToken> {

    public TestIDBClient(Configuration conf) {
    }

    @Override
    public String getGatewayAddress() {
      return null;
    }

    @Override
    public Pair<KnoxSession, String> login(Configuration configuration) throws IOException {
      return null;
    }

    @Override
    public AccessTokenProvider.AccessToken extractCloudCredentialsFromResponse(BasicResponse basicResponse) throws IOException {
      return null;
    }

    @Override
    public KnoxSession cloudSessionFromDT(String delegationToken, String endpointCert) throws IOException {
      return null;
    }

    @Override
    public CloudAccessBrokerSession cloudSessionFromDelegationToken(String delegationToken, String endpointCert) throws IOException {
      return null;
    }

    @Override
    public CloudAccessBrokerSession cloudSessionFromDelegationToken(String delegationToken, String delegationTokenType, String endpointCert) throws IOException {
      return null;
    }

    @Override
    public AccessTokenProvider.AccessToken fetchCloudCredentials(CloudAccessBrokerSession session) throws IOException {
      return null;
    }

    @Override
    public IDBMethod determineIDBMethodToCall() {
      return null;
    }

    @Override
    public RequestDTResponseMessage requestKnoxDelegationToken(KnoxSession dtSession, String origin, URI fsUri) throws IOException {
      return null;
    }

    @Override
    public RequestDTResponseMessage updateDelegationToken(String delegationToken, String delegationTokenType, String cabPublicCert) throws Exception {
      return null;
    }
  }

  static class TestCloudAccessBrokerClient implements CloudAccessBrokerClient {

    public TestCloudAccessBrokerClient(Configuration conf) {
    }

    @Override
    public String getCloudAccessBrokerAddress() {
      return null;
    }

    @Override
    public CloudAccessBrokerSession getCloudSession(String delegationToken,
                                                    String delegationTokenType)
        throws URISyntaxException {
      return null;
    }

    @Override
    public CloudAccessBrokerSession getCloudSession(String delegationToken,
                                                    String delegationTokenType,
                                                    String cabPublicCert)
        throws URISyntaxException {
      return null;
    }

    @Override
    public RequestDTResponseMessage requestDelegationToken(KnoxSession dtSession)
        throws IOException {
      return null;
    }

    @Override
    public RequestDTResponseMessage updateDelegationToken(String delegationToken,
                                                          String delegationTokenType,
                                                          String cabPublicCert)
        throws Exception {
      return null;
    }

    @Override
    public KnoxSession createDTSession(String gatewayCertificate)
        throws IllegalStateException {
      return null;
    }

    @Override
    public KnoxSession createUsernamePasswordDTSession() {
      return null;
    }

    @Override
    public KnoxSession createKerberosDTSession(String gatewayCertificate)
        throws URISyntaxException {
      return null;
    }

    @Override
    public AccessTokenProvider.AccessToken getCloudCredentials(CloudAccessBrokerSession session)
        throws IOException {
      return null;
    }
  }

}
