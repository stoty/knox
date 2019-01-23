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
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
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
    Closeable {

  protected static final Logger LOG =
      LoggerFactory.getLogger(AbfsIDBCredentialProvider.class);

  private AbfsIDBIntegration integration;

  @Override
  public void initialize(final Configuration configuration,
      final String accountName)
      throws IOException {

    integration = AbfsIDBIntegration.fromAbfsCredentialProvider(
        AbfsIDBIntegration.FS_URI,
        configuration,
        accountName);
  }

  @Override
  public void close() {
    IOUtils.cleanupWithLogger(LOG, integration);
  }

  @Override
  public String getAccessToken() throws IOException {
    return integration.getADTokenString();
  }

  @Override
  public Date getExpiryTime() {
    return integration.getADTokenExpiryTime();
  }
}
