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

import com.google.cloud.hadoop.fs.gcs.GoogleHadoopFileSystem;
import com.google.cloud.hadoop.fs.gcs.GoogleHadoopFileSystemConfiguration;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.hadoop.test.HadoopTestBase;
import org.apache.knox.test.category.VerifyTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Locale;

import static java.util.Objects.requireNonNull;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.createTestConfiguration;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CAB_TOKEN_KIND;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_DT_PASS;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_DT_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.CAB_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.CREDENTIAL_PROVIDER_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.DT_AUTH_PASS;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.DT_AUTH_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.requireTestBucket;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.requireTestProject;

@Category(VerifyTest.class)
public class ITestGCPCABDelegationTokenBinding extends HadoopTestBase {

  protected static final Logger LOG =
      LoggerFactory.getLogger(ITestGCPCABDelegationTokenBinding.class);

  private Configuration configuration;

  private GoogleHadoopFileSystem fs;

  private Configuration getConfiguration() {
    return configuration;
  }

  protected Configuration createConfiguration() {

    Configuration conf = createTestConfiguration();
    final String myTestProject = requireTestProject(configuration);

    conf.set(GoogleHadoopFileSystemConfiguration.GCS_PROJECT_ID.getKey(), myTestProject);
    conf.set(GoogleHadoopFileSystemConfiguration.AUTH_CLIENT_ID.getKey(), "fooclient");

    // If the client trust store is configured, apply it
    if (CloudAccessBrokerClientTestUtils.TRUST_STORE_LOCATION != null) {
      conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_LOCATION,
          CloudAccessBrokerClientTestUtils.TRUST_STORE_LOCATION);
    }

    if (!CREDENTIAL_PROVIDER_PATH.isEmpty()) {
      conf.set("hadoop.security.credential.provider.path",
          CREDENTIAL_PROVIDER_PATH);
    }


    enableDelegationTokens(conf,
        CABDelegationTokenBinding.class.getName());
    set(conf, CONFIG_CAB_ADDRESS, CLOUD_ACCESS_BROKER_ADDRESS);
    set(conf, CONFIG_CAB_PATH, CAB_PATH);
    set(conf, CONFIG_CAB_DT_PATH, DT_PATH);
    set(conf, CONFIG_DT_USERNAME, DT_AUTH_USERNAME);
    set(conf, CONFIG_DT_PASS, DT_AUTH_PASS);
    return conf;
  }

  /**
   * Set a config option, logging @ debug first.
   *
   * @param conf
   * @param key
   * @param val
   */
  private void set(Configuration conf, String key, String val) {
    LOG.debug("setting {}=\"{}\"", key, val);
    conf.set(key, val);
  }

  @Before
  public void setUp() throws Exception {
    resetUGI();
    configuration = createConfiguration();
    final String myTestBucket = requireTestBucket(configuration);
    fs = new GoogleHadoopFileSystem();
    fs.initialize(new URI(myTestBucket), configuration);
  }


  @After
  public void tearDown() throws Exception {
    resetUGI();
    IOUtils.closeStreams(fs);
  }

  /**
   * Patch the current config with the DT binding.
   *
   * @param conf    configuration to patch
   * @param binding binding to use
   */
  protected void enableDelegationTokens(Configuration conf,
                                        String binding) {
    LOG.info("Enabling delegation token support for {}", binding);
    conf.set(GoogleHadoopFileSystemConfiguration.DELEGATION_TOKEN_BINDING_CLASS.getKey(), binding);
  }

  /**
   * Reset UGI info.
   */
  protected void resetUGI() {
    UserGroupInformation.reset();
  }

  /**
   * Save a DT to a file.
   *
   * @param tokenFile destination file
   * @param token     token to save
   * @throws IOException failure
   */
  protected void saveDT(final File tokenFile, final Token<?> token)
      throws IOException {
    requireNonNull(token, "Null token");
    Credentials cred = new Credentials();
    cred.addToken(token.getService(), token);

    try (OutputStream fos = Files.newOutputStream(tokenFile.toPath());
         DataOutputStream out = new DataOutputStream(fos)) {
      cred.writeTokenStorageToStream(out);
    }
  }

  @Test
  public void testSaveLoadTokens() throws Throwable {
    File tokenFile = File.createTempFile("token", "bin");

    Token<? extends TokenIdentifier> dt = fs.getDelegationToken(null);
    final Text serviceId = dt.getService();

    final CABGCPTokenIdentifier origIdentifier = (CABGCPTokenIdentifier) dt.decodeIdentifier();
    assertEquals("kind in " + dt, CAB_TOKEN_KIND, dt.getKind());

    GoogleTempCredentials marshalled = origIdentifier.getMarshalledCredentials();
    long expiration = marshalled.getExpiration();
    LocalDateTime expiryDate = LocalDateTime.from(Instant.ofEpochMilli(expiration));
    LocalDateTime currentDate = LocalDateTime.now(Clock.systemDefaultZone());
    String expires = String.format(Locale.ROOT, "%s (%d)", expiryDate, expiration);
    assertEquals("wrong month for " + expires, currentDate.getMonth(), expiryDate.getMonth());

    // Marshall the token
    saveDT(tokenFile, dt);
    assertTrue("Empty token file", tokenFile.length() > 0);

    // Unmarshall the token
    Credentials creds = Credentials.readTokenStorageFile(tokenFile, getConfiguration());

    // Validate the token
    Token<? extends TokenIdentifier> token =
        requireNonNull(creds.getToken(serviceId),
            () -> "No token for \"" + serviceId + "\" in: " + creds.getAllTokens());
    CABGCPTokenIdentifier dtId = (CABGCPTokenIdentifier) token.decodeIdentifier();
    assertEquals("token identifier ", origIdentifier, dtId);
    assertEquals("Origin in " + dtId, origIdentifier.getOrigin(), dtId.getOrigin());
  }
}
