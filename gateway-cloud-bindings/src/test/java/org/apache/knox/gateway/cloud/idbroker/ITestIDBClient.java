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

import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.knox.gateway.shell.KnoxSession;

/**
 * Talk to the IDB client and request a DT for it.
 */
public class ITestIDBClient {

  protected static final Logger LOG =
      LoggerFactory.getLogger(IDBClient.class);
  
  @Rule
  public TestName methodName = new TestName();

  /**
   * Set the timeout for every test.
   */
  @Rule
  public Timeout testTimeout = new Timeout(600 * 1000, TimeUnit.MILLISECONDS);

  private IDBClient idbClient;

  private KnoxSession knoxSession;

  @BeforeClass
  public static void classSetup() throws Exception {
    Thread.currentThread().setName("JUnit");
  }

  @Before
  public void setup() throws Throwable {
    Configuration configuration = new Configuration();
    String gateway = configuration.get(IDBConstants.IDBROKER_GATEWAY,
        IDBConstants.LOCAL_GATEWAY);
    LOG.info("Using gateway {}", gateway);
    idbClient = new IDBClient(gateway,
        IDBConstants.DEFAULT_CERTIFICATE_PATH,
        IDBConstants.DEFAULT_CERTIFICATE_PASSWORD);
    knoxSession = KnoxSession.login(idbClient.dtURL(),
        IDBConstants.ADMIN_USER,
        IDBConstants.ADMIN_PASSWORD,
        idbClient.getTruststorePath(),
        IDBConstants.DEFAULT_CERTIFICATE_PASSWORD);
  }
  
  @Test
  public void testRequestDT() throws Throwable {
    idbClient.requestKnoxDelegationToken(knoxSession).validate();
  }

  @Test
  public void testFetchAWSCredentials() throws Throwable {
    String knoxDT = idbClient
        .requestKnoxDelegationToken(knoxSession).validate().access_token;
    KnoxSession cloudSession = idbClient.cloudSessionFromDT(knoxDT);
    idbClient.fetchAWSCredentials(cloudSession);

    MarshalledCredentials awsCredentials =
        idbClient.fetchAWSCredentials(cloudSession);
    awsCredentials.validate("No creds",
        MarshalledCredentials.CredentialTypeRequired.SessionOnly);
  }

  @Test
  public void testRequestAWSFromKnoxDT() throws Throwable {
    String knoxDT = idbClient
        .requestKnoxDelegationToken(knoxSession).validate().access_token;
    KnoxSession cloudSession = idbClient.cloudSessionFromDT(knoxDT);
    idbClient.fetchAWSCredentials(cloudSession);
  }

  
}
