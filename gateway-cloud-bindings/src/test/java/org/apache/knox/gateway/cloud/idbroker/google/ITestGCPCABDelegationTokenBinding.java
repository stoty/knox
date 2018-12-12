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
import com.google.cloud.hadoop.fs.gcs.auth.GCSDelegationTokens;
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
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Date;

import static java.util.Objects.requireNonNull;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.createTestConfiguration;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.*;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.requireTestBucket;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.requireTestProject;

@Category(VerifyTest.class)
public class ITestGCPCABDelegationTokenBinding extends HadoopTestBase {

  protected static final Logger LOG =
      LoggerFactory.getLogger(ITestGCPCABDelegationTokenBinding.class);

  private Configuration configuration;

  private GCSDelegationTokens delegationTokens;

  private GoogleHadoopFileSystem fs;

  private Configuration getConfiguration() {
    return configuration;
  }

  protected Configuration createConfiguration() {

    Configuration conf = createTestConfiguration();
    final String myTestProject = requireTestProject(configuration);


    conf.set(GoogleHadoopFileSystem.GCS_PROJECT_ID_KEY, myTestProject);
    conf.set("fs.gs.auth.client.id", "fooclient");

    // If the client trust store is configured, apply it
    if (CloudAccessBrokerClientTestUtils.TRUST_STORE_LOCATION != null) {
      conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_LOCATION,
               CloudAccessBrokerClientTestUtils.TRUST_STORE_LOCATION);
    }

    conf.set("hadoop.security.credential.provider.path", CloudAccessBrokerClientTestUtils.CREDENTIAL_PROVIDER_PATH);

    enableDelegationTokens(conf,
                           CABDelegationTokenBinding.class.getName());
    conf.set(CONFIG_CAB_ADDRESS, "https://localhost:8443/gateway");
    conf.set(CONFIG_CAB_PATH, "gcp-cab");
    conf.set(CONFIG_CAB_DT_PATH, "dt");
    conf.set(CONFIG_DT_USERNAME, "admin");
    conf.set(CONFIG_DT_PASS, "");
    return conf;
  }

  @Before
  public void setup() throws Exception {
    resetUGI();
    configuration = createConfiguration();
    final String myTestBucket = requireTestBucket(configuration);
    fs = new GoogleHadoopFileSystem();
    fs.initialize(new URI("gs://" + myTestBucket + "/"), configuration);
  }


  @After
  public void teardown() throws Exception {
    resetUGI();
    IOUtils.closeStreams(fs);
  }

  /**
   * Patch the current config with the DT binding.
   * @param conf configuration to patch
   * @param binding binding to use
   */
  protected void enableDelegationTokens(Configuration conf,
                                        String        binding) {
    LOG.info("Enabling delegation token support for {}", binding);
    conf.set(GCSDelegationTokens.CONFIG_DELEGATION_TOKEN_BINDING_CLASS, binding);
  }

  /**
   * Reset UGI info.
   */
  protected void resetUGI() {
    UserGroupInformation.reset();
  }

  /**
   * Save a DT to a file.
   * @param tokenFile destination file
   * @param token token to save
   * @throws IOException failure
   */
  protected void saveDT(final File tokenFile, final Token<?> token)
      throws IOException {
    requireNonNull(token, "Null token");
    Credentials cred = new Credentials();
    cred.addToken(token.getService(), token);

    try (DataOutputStream out = new DataOutputStream(new FileOutputStream(tokenFile))) {
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
    Date expiryDate = new Date(expiration);
    Date currentDate = new Date(System.currentTimeMillis());
    String expires = String.format("%s (%d)", expiryDate, expiration);
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
