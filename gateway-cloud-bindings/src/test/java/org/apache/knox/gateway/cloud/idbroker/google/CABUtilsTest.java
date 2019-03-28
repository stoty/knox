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
import java.nio.charset.StandardCharsets;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.cloud.idbroker.IDBTestUtils;

import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.KnoxSession;
import org.junit.Test;

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CAB_TOKEN_KIND;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

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
    validateURL(expectedURL, CABUtils.getCloudAccessBrokerURL(config));
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
    validateURL(expectedURL, CABUtils.getDelegationTokenProviderURL(config));
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
    CloudAccessBrokerClient client = CABUtils.newClient(new Configuration());
    assertNotNull(client);
    assertEquals(GCPCABClient.class, client.getClass());
  }

  @Test
  public void testGetConfiguredClient() {
    Configuration conf = new Configuration();
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CLIENT_IMPL, TestCloudAccessBrokerClient.class.getName());
    CloudAccessBrokerClient client = CABUtils.newClient(conf);
    assertNotNull(client);
    assertEquals(TestCloudAccessBrokerClient.class, client.getClass());
  }


  static class TestCloudAccessBrokerClient implements CloudAccessBrokerClient {

    public TestCloudAccessBrokerClient(Configuration conf) {
    }

    @Override
    public KnoxSession getCloudSession(String cabAddress,
                                       String delegationToken,
                                       String delegationTokenType,
                                       String trustStoreLocation,
                                       String trustStorePass) throws URISyntaxException {
      return null;
    }

    @Override
    public KnoxSession getCloudSession(String cabAddress,
                                       String delegationToken,
                                       String delegationTokenType,
                                       String cabPublicCert) throws URISyntaxException {
      return null;
    }

    @Override
    public RequestDTResponseMessage requestDelegationToken(KnoxSession dtSession) throws IOException {
      return null;
    }

    @Override
    public RequestDTResponseMessage updateDelegationToken(String delegationToken,
                                                          String delegationTokenType,
                                                          String cabPublicCert) throws Exception {
      return null;
    }

    @Override
    public KnoxSession createDTSession(String gatewayCertificate) throws IllegalStateException {
      return null;
    }

    @Override
    public KnoxSession createUsernamePasswordDTSession(String dtAddress) {
      return null;
    }

    @Override
    public KnoxSession createKerberosDTSession(String dtAddress, String gatewayCertificate) throws URISyntaxException {
      return null;
    }

    @Override
    public AccessTokenProvider.AccessToken getCloudCredentials(KnoxSession session) throws IOException {
      return null;
    }
  }

}
