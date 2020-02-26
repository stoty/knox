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

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_TEST_TOKEN_PATH;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.hadoop.fs.gcs.GoogleHadoopFileSystemBase;
import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

public class TestCABDelegationTokenBinding extends CABDelegationTokenBinding {
  TokenProvider accessTokenProvider;

  private boolean getTestToken;
  private Path testTokenPath;

  public void setClient(final IDBClient<AccessTokenProvider.AccessToken> client) {
    cabClient = client;
  }

  @Override
  public void bindToFileSystem(GoogleHadoopFileSystemBase fs, Text service) {
    super.bindToFileSystem(fs, service);

    LOG.warn("This implementation of the CABDelegationTokenBinding is for testing purposes only");

    Configuration configuration = getConf();
    String propertyValue = configuration.getTrimmed(CONFIG_TEST_TOKEN_PATH);

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
  TokenProvider getAccessTokenProvider() {
    if(accessTokenProvider == null) {
      accessTokenProvider = new TestAccessTokenProvider(super.getAccessTokenProvider());
    }
    return accessTokenProvider;
  }

  @Override
  synchronized GoogleTempCredentials updateGCPCredentials() throws IOException {
    GoogleTempCredentials token;

    if (getTestToken) {
      token = readTestToken();
      // Toggle the test token if called with renewIfNeeded=true more then once...
      getTestToken = false;
    } else {
      token = null;
    }

    if (token == null) {
      LOG.warn("This implementation of the CABDelegationTokenBinding is for testing purposes only - using REAL access token");
      return super.updateGCPCredentials();
    } else {
      LOG.warn("This implementation of the CABDelegationTokenBinding is for testing purposes only - using TEST access token");
      return token;
    }
  }

  private GoogleTempCredentials readTestToken() throws IOException {
    Map<String, Object> map;

    if (testTokenPath != null) {
      try (InputStream inputStream = Files.newInputStream(testTokenPath)) {
        ObjectMapper om = new ObjectMapper();
        map = om.readValue(inputStream, new TypeReference<Map<String, Object>>() {
        });
      }
    } else {
      map = null;
    }

    if (map != null) {
      String accessToken = (String) map.get("accessToken");
      String expireTime = (String) map.get("expireTime");
      long expirationDateTime = DateTime.parseRfc3339(expireTime).getValue();
      return new GoogleTempCredentials(new AccessTokenProvider.AccessToken(accessToken, expirationDateTime));
    } else {
      return null;
    }
  }

}
