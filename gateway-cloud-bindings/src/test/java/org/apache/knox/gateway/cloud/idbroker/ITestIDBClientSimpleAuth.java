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

package org.apache.knox.gateway.cloud.idbroker;

import java.io.IOException;

import org.junit.experimental.categories.Category;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.test.category.VerifyTest;

import static org.apache.knox.gateway.cloud.idbroker.IDBClient.createFullIDBClient;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.TEST_ADMIN_PASS;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.TEST_ADMIN_USER;

@Category(VerifyTest.class)
public class ITestIDBClientSimpleAuth extends AbstractITestIDBClient {

  @Override
  protected String getOrigin() {
    return "simple username and password login as " + TEST_ADMIN_USER;
  }

  /**
   * Create the IDB Client.
   * @param configuration configuration to use
   * @return an instantiated IDB Client.
   * @throws IOException failure
   */
  @Override
  protected IDBClient createIDBClient(final Configuration configuration)
      throws IOException {
    LOG.info(getOrigin());
    return createFullIDBClient(configuration,
        UserGroupInformation.getCurrentUser());
  }

  /**
   * Create the Knox session;
   * will be invoked after {@link #createIDBClient(Configuration)}.
   * @return an instantiated Knox session
   * @throws IOException failure
   */
  @Override
  protected KnoxSession createKnoxSession() throws IOException {
    return getIdbClient().knoxSessionFromSecrets(TEST_ADMIN_USER,
                                        TEST_ADMIN_PASS);
  }
}
