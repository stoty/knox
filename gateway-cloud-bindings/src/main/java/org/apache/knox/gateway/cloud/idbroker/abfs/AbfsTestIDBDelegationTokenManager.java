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

public class AbfsTestIDBDelegationTokenManager extends AbfsIDBDelegationTokenManager {

  private static final Logger LOG = LoggerFactory.getLogger(AbfsTestIDBDelegationTokenManager.class);

  @Override
  public void initialize(final Configuration configuration) throws IOException {
    LOG.warn("This implementation of the AbfsIDBDelegationTokenManager is for testing purposes only");
    super.initialize(configuration);
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
    LOG.warn("This implementation of the AbfsIDBDelegationTokenManager is for testing purposes only");
    super.setIntegration(AbfsTestIDBIntegration.fromDelegationTokenManager(uri, conf));
  }
}
