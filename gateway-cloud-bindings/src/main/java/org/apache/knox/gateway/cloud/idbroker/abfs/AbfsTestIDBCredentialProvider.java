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

import org.apache.hadoop.conf.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.util.Date;

/**
 * Provider of the credentials needed for ABFS to authenticate with the given
 * account name.
 * <p>
 * This initial attempt tries to do things on the original interface,
 * to show what extra information is going to be needed.
 */
public class AbfsTestIDBCredentialProvider extends AbfsIDBCredentialProvider {

  private static final Logger LOG = LoggerFactory.getLogger(AbfsTestIDBCredentialProvider.class);

  @Override
  public void initialize(Configuration conf, String account) throws IOException {
    LOG.warn("This implementation of the AbfsIDBCredentialProvider is for testing purposes only");
    super.initialize(conf, account);
  }

  /**
   * Bind to the given URI.
   *
   * @param uri  FS URI
   * @param conf configuration
   * @throws IOException failure
   */
  @Override
  public void bind(final URI uri, final Configuration conf)
      throws IOException {

    LOG.debug("Binding to URI {}", uri);
    setIntegration(AbfsTestIDBIntegration.fromAbfsCredentialProvider(uri, conf));
  }

  @Override
  public String getAccessToken() throws IOException {
    return super.getAccessToken();
  }

  @Override
  public Date getExpiryTime() {
    return super.getExpiryTime();
  }
}
