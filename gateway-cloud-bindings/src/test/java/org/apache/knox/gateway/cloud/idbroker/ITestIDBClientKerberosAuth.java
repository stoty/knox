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

import static org.junit.Assume.assumeTrue;

@Category(VerifyTest.class)
public class ITestIDBClientKerberosAuth extends AbstractITestIDBClient {

  /**
   * Create the IDB Client.
   * @param configuration configuration to use
   * @return an instantiated IDB Client.
   * @throws IOException failure
   */
  @Override
  protected IDBClient createIDBClient(final Configuration configuration)
      throws IOException {
    UserGroupInformation currentUser = UserGroupInformation.getCurrentUser();
    if (!currentUser.hasKerberosCredentials()) {

      LOG.info("Current user is not using Kerberos {}", currentUser);
      assumeTrue("Current user is not using Kerberos: " + currentUser,
          false);
    }
    LOG.info("Logging in as {}", currentUser.getUserName());
    
    return new IDBClient(configuration);
  }

  @Override
  protected KnoxSession createKnoxSession() throws IOException {
    return getIdbClient().knoxDtSession();
  }
}
