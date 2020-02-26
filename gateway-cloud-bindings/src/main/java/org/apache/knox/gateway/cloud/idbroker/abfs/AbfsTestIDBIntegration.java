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

package org.apache.knox.gateway.cloud.idbroker.abfs;

import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_TEST_TOKEN_PATH;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.azurebfs.oauth2.AzureADToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;

class AbfsTestIDBIntegration extends AbfsIDBIntegration {
  private static final Logger LOG = LoggerFactory.getLogger(AbfsTestIDBIntegration.class);

  private final Path testTokenPath;
  private boolean getTestToken;
  private AzureADToken testToken;

  private AbfsIDBClient testClient;

  /**
   * Create as part of the binding process for an Azure Delegation Token manager.
   *
   * @param fsUri filesystem URI.
   * @param conf  configuration.
   * @return a started instance.
   * @throws IOException failure
   */
  static AbfsTestIDBIntegration fromDelegationTokenManager(
      final URI fsUri,
      final Configuration conf) throws IOException {
    AbfsTestIDBIntegration integration = new AbfsTestIDBIntegration(fsUri, conf, "DelegationTokenManager");
    integration.init(conf);
    integration.start();
    return integration;
  }

  /**
   * Create as part of the binding process of an Azure credential provider.
   *
   * @param fsUri filesystem URI.
   * @param conf  configuration.
   * @return a started instance.
   * @throws IOException failure
   */
  static AbfsTestIDBIntegration fromAbfsCredentialProvider(
      final URI fsUri,
      final Configuration conf) throws IOException {
    AbfsTestIDBIntegration integration = new AbfsTestIDBIntegration(fsUri, conf, "CredentialProvider");
    integration.init(conf);
    integration.start();
    return integration;
  }


  AbfsTestIDBIntegration(@Nonnull URI fsUri, @Nonnull Configuration configuration, @Nonnull String origin) throws IOException {
    this(fsUri, configuration, origin, null);
  }

  AbfsTestIDBIntegration(@Nonnull URI fsUri, @Nonnull Configuration configuration, @Nonnull String origin, AbfsIDBClient client) throws IOException {
    super("AbfsTestIDBIntegration", fsUri, configuration, origin);
    LOG.warn("This implementation of the AbfsIDBIntegration is for testing purposes only");

    if (client != null) {
      testClient = client;
    }

    String propertyValue = configuration.getTrimmed(IDBROKER_TEST_TOKEN_PATH.getPropertyName());

    if (StringUtils.isNotEmpty(propertyValue)) {
      Path path = Paths.get(propertyValue);

      if (!Files.exists(path)) {
        LOG.warn("The specified path does not exist, a test token will not be used: {}", path.toAbsolutePath());
        testTokenPath = null;
      } else if (!Files.isRegularFile(path)) {
        LOG.warn("The specified path is not a file, a test token will not be used: {}", path.toAbsolutePath());
        testTokenPath = null;
      } else if (!Files.isReadable(path)) {
        LOG.warn("The specified file is not readable, a test token will not be used: {}", path.toAbsolutePath());
        testTokenPath = null;
      } else {
        testTokenPath = path;
        LOG.warn("Using test access token from {}", testTokenPath.toAbsolutePath());
      }
    } else {
      LOG.warn("A file for a test token was not specified, a test token will not be used");
      testTokenPath = null;
    }

    getTestToken = (testTokenPath != null);
  }

  @Override
  protected AbfsIDBClient getClient() throws IOException {
    return (testClient != null ? testClient : super.getClient());
  }

  @Override
  AzureADToken getADToken(boolean renewIfNeeded) throws IOException {
    AzureADToken token;

    if (getTestToken) {
      testToken = readTestToken();
    }

    if (renewIfNeeded) {
      // Toggle the test token if called with renewIfNeeded=true more then once...
      if (getTestToken) {
        getTestToken = false;
      } else {
        testToken = null;
      }
    }

    token = testToken;

    if (token == null) {
      LOG.warn("This implementation of the AbfsIDBIntegration is for testing purposes only - using REAL access token");
      return super.getADToken(renewIfNeeded);
    } else {
      LOG.warn("This implementation of the AbfsIDBIntegration is for testing purposes only - using TEST access token");
      return token;
    }
  }

  private AzureADToken readTestToken() throws IOException {
    AbfsAuthResponseMessage responseMessage;

    if (testTokenPath != null) {
      try (InputStream inputStream = Files.newInputStream(testTokenPath)) {
        responseMessage = AbfsAuthResponseMessage
            .serializer()
            .fromJsonStream(inputStream);
      }
    } else {
      responseMessage = null;
    }

    if (responseMessage != null) {
      AzureADToken testToken = new AzureADToken();
      testToken.setAccessToken(responseMessage.getAccessToken());
      testToken.setExpiry(Date.from(responseMessage.getExpiry()));
      return testToken;
    } else {
      return null;
    }
  }
}
