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

import java.io.Closeable;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
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
public class AbfsIDBDelegationTokenIssuer 
    implements CustomDelegationTokenManager, Closeable {

  protected static final Logger LOG =
      LoggerFactory.getLogger(AbfsIDBDelegationTokenIssuer.class);

  private AbfsIDBIntegration integration;
  
  @Override
  public void initialize(final Configuration configuration) throws IOException {
    integration = AbfsIDBIntegration.fomDTIssuer(
        AbfsIDBIntegration.FS_URI,
        configuration);
  }

  @Override
  public void close() throws IOException {
    IOUtils.cleanupWithLogger(LOG, integration);
  }

  /**
   * There is some ugliness going on here to defeat javac's type inference.
   * The superclass needs tobe made more generic.
   */
  @Override
  public Token<DelegationTokenIdentifier> getDelegationToken(final String renewer)
      throws IOException {
    Token<AbfsIDBTokenIdentifier> token
        = integration.getDelegationToken(renewer);
    return (Token<DelegationTokenIdentifier>)
        (Token) token;
  }

  @Override
  public long renewDelegationToken(final Token<?> token) throws IOException {
    return 0;
  }

  @Override
  public void cancelDelegationToken(final Token<?> token) throws IOException {

  }
}
