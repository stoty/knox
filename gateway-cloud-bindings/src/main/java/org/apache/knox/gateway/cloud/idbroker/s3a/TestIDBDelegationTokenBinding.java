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

import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_TEST_TOKEN_PATH;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.AWSCredentialProviderList;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractS3ATokenIdentifier;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class TestIDBDelegationTokenBinding extends IDBDelegationTokenBinding {
  private Path testTokenPath;
  private boolean getTestToken;
  private S3AIDBClient mockIdbClient;

  public TestIDBDelegationTokenBinding() {
    super();
  }

  public TestIDBDelegationTokenBinding(String name, Text kind) {
    super(name, kind);
  }

  void setMockIdbClient(S3AIDBClient mockIdbClient) {
    this.mockIdbClient = mockIdbClient;
  }

  @Override
  protected S3AIDBClient getIdbClient() {
    return this.mockIdbClient == null ? super.getIdbClient() : this.mockIdbClient;
  }

  @Override
  public AWSCredentialProviderList deployUnbonded() throws IOException {
    loadTestToken();
    return super.deployUnbonded();
  }

  @Override
  public AWSCredentialProviderList bindToTokenIdentifier(AbstractS3ATokenIdentifier retrievedIdentifier) throws IOException {
    loadTestToken();
    return super.bindToTokenIdentifier(retrievedIdentifier);
  }

  private void loadTestToken() {

    LOG.warn("This implementation of the IDBDelegationTokenBinding is for testing purposes only");

    Configuration configuration = getConfig();
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
  protected MarshalledCredentials fetchMarshalledAWSCredentials(S3AIDBClient client,
                                                                CloudAccessBrokerSession dtSession)
      throws IOException {
    MarshalledCredentials testToken;

    // Toggle the test token if called more then once...
    if (getTestToken) {
      testToken = readTestToken(client);
      getTestToken = false;
    } else {
      testToken = null;
    }

    if (testToken == null) {
      LOG.warn("This implementation of the AbfsIDBIntegration is for testing purposes only - using REAL access token");
      return super.fetchMarshalledAWSCredentials(client, dtSession);
    } else {
      LOG.warn("This implementation of the AbfsIDBIntegration is for testing purposes only - using TEST access token");
      return testToken;
    }
  }

  private MarshalledCredentials readTestToken(S3AIDBClient s3AIDBClient) throws IOException {
    AuthResponseAWSMessage responseMessage;

    if (testTokenPath != null) {
      try (InputStream inputStream = Files.newInputStream(testTokenPath)) {
        responseMessage = AuthResponseAWSMessage
            .serializer()
            .fromJsonStream(inputStream);
      }
    } else {
      responseMessage = null;
    }

    if (responseMessage != null) {
      return s3AIDBClient.responseToMarshalledCredentials(responseMessage);
    } else {
      return null;
    }
  }
}
