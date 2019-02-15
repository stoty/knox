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

import java.io.IOException;
import java.net.URI;
import java.util.Date;

import com.google.common.base.Preconditions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.azurebfs.extensions.BoundDTExtension;
import org.apache.hadoop.fs.azurebfs.extensions.CustomDelegationTokenManager;
import org.apache.hadoop.fs.azurebfs.extensions.CustomTokenProviderAdaptee;
import org.apache.hadoop.io.IOUtils;

/**
 * Provider of the credentials needed for ABFS to authenticate with the given
 * account name.
 *
 * This initial attempt tries to do things on the original interface,
 * to show what extra information is going to be needed.
 */
public class AbfsIDBCredentialProvider implements CustomTokenProviderAdaptee,
    BoundDTExtension {

  protected static final Logger LOG =
      LoggerFactory.getLogger(AbfsIDBCredentialProvider.class);

  public static final String NAME =
      "org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBCredentialProvider";

  private AbfsIDBIntegration integration;

  private String accountName;
  
  @Override
  public void initialize(final Configuration conf,
      final String account)
      throws IOException {
   this.accountName = account;
  }

  /**
   * Bind to the given URI.
   * @param uri FS URI
   * @param conf configuration
   * @throws IOException failure
   */
  //  @Override
  public void bind(final URI uri, final Configuration conf)
      throws IOException {

    LOG.debug("Binding to URI {}", uri);
    integration = AbfsIDBIntegration.fromAbfsCredentialProvider(
        uri,
        conf,
        accountName);
  }

  private void checkBound() {
    Preconditions.checkState(integration != null,
        "Credential Provider is not bound");
  }
  
  @Override
  public void close() {
    IOUtils.cleanupWithLogger(LOG, integration);
    integration = null;
  }

  @Override
  public String getAccessToken() throws IOException {
    checkBound();
    return integration.getADTokenString();
  }

  @Override
  public Date getExpiryTime() {
    checkBound();
    return integration.getADTokenExpiryTime();
  }

  /**
   * Get the canonical service name, which will be
   * returned by {@code FileSystem.getCanonicalServiceName()} and so used to 
   * map the issued DT in credentials, including credential files collected
   * for job submission.
   *
   * If null is returned: fall back to the default filesystem logic.
   *
   * Only invoked on {@link CustomDelegationTokenManager} instances.
   * @return the service name to be returned by the filesystem. 
   */
  @Override
  public String getCanonicalServiceName() {
    checkBound();
    return integration.getCanonicalServiceName();
  }

  /**
   * Get a suffix for the UserAgent suffix of HTTP requests, which
   * can be used to identify the principal making ABFS requests.
   * @return an empty string, or a key=value string to be added to the UA
   * header.
   */
  @Override
  public String getUserAgentSuffix() {
    checkBound();
    return integration.getUserAgentSuffix();
  }
}
