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

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.test.HadoopTestBase;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.test.category.VerifyTest;

/**
 * Talk to the IDB client and request a DT for it.
 */
@Category(VerifyTest.class)
public class ITestIDBClient extends HadoopTestBase {

  protected static final Logger LOG =
      LoggerFactory.getLogger(ITestIDBClient.class);

  private IDBClient idbClient;

  private KnoxSession knoxSession;

  @Before
  public void setup() throws Throwable {
	Configuration configuration = new Configuration();

	// Skip these tests if the expected configuration is not present
  org.junit.Assume.assumeNotNull(configuration.get("fs.contract.test.fs.s3a"));

//    configuration.set(IDBConstants.IDBROKER_GATEWAY, "https://ctr-e139-1542663976389-22700-01-000003.hwx.site:8443/gateway/");
    String gateway = configuration.get(IDBConstants.IDBROKER_GATEWAY,
        IDBConstants.LOCAL_GATEWAY);
    LOG.info("Using gateway {}", gateway);
    idbClient = new IDBClient(configuration);
    knoxSession = KnoxSession.login(idbClient.dtURL(),
        IDBConstants.ADMIN_USER,
        IDBConstants.ADMIN_PASSWORD,
        idbClient.getTruststorePath(),
        idbClient.getTruststorePass());
  }
  
  @Test
  public void testRequestDT() throws Throwable {
    idbClient.requestKnoxDelegationToken(knoxSession).validate();
  }

  @Test
  public void testRequestAWSFromKnoxDT() throws Throwable {
    String knoxDT = idbClient
        .requestKnoxDelegationToken(knoxSession).validate().access_token;
    KnoxSession cloudSession = idbClient.cloudSessionFromDT(knoxDT);
    MarshalledCredentials awsCredentials = 
        idbClient.fetchAWSCredentials(cloudSession);
    awsCredentials.validate("No creds",
        MarshalledCredentials.CredentialTypeRequired.SessionOnly);
  }
}
