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

import com.google.common.base.Preconditions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.azurebfs.extensions.BoundDTExtension;
import org.apache.hadoop.fs.azurebfs.extensions.CustomDelegationTokenManager;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenIdentifier;

/**
 * The DT provider for ABFS. 
 * Initially uses the limited interface offered by the initial ABFS
 * entry point, where the name of the target FS is unknown.
 * We have to issue a DT with a common name.
 */
public class AbfsIDBDelegationTokenManager 
    implements CustomDelegationTokenManager, BoundDTExtension {

  protected static final Logger LOG =
      LoggerFactory.getLogger(AbfsIDBDelegationTokenManager.class);

  public static final String NAME =
      "org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBDelegationTokenManager";
  private AbfsIDBIntegration integration;
  
  @Override
  public void initialize(final Configuration configuration) throws IOException {
  }

  /**
   * Bind to the given URI.
   * @param uri FS URI
   * @param conf configuration
   * @throws IOException failure
   */
  @Override
  public void bind(final URI uri, final Configuration conf)
      throws IOException {

    LOG.debug("Binding to URI {}", uri);
    integration = AbfsIDBIntegration.fromDelegationTokenManager(
        uri,
        conf);
  }

  @Override
  public void close() throws IOException {
    IOUtils.cleanupWithLogger(LOG, integration);
  }

  private void checkBound() {
    Preconditions.checkState(integration != null,
        "Credential Provider is not bound");
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
    return "";
  }
  
  /**
   * There is some ugliness going on here to defeat javac's type inference.
   * The superclass needs to be made more generic.
   */
  @Override
  public Token<DelegationTokenIdentifier> getDelegationToken(final String renewer)
      throws IOException {
    checkBound();
    Token<AbfsIDBTokenIdentifier> token
        = integration.getDelegationToken(renewer);
    return (Token<DelegationTokenIdentifier>)
        (Token) token;
  }

  @Override
  public long renewDelegationToken(final Token<?> token) throws IOException {
    // no-op
    return 0;
  }

  @Override
  public void cancelDelegationToken(final Token<?> token) throws IOException {
    // no-op
  }
}
