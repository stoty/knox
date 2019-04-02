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

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.test.HadoopTestBase;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.test.category.UnitTests;
import org.easymock.EasyMock;

import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.createUnitTestConfiguration;

/**
 * Talk to the IDB client and request a DT for it.
 */
@Category(UnitTests.class)
public class TestIDBClient extends HadoopTestBase {

  protected static final Logger LOG =
      LoggerFactory.getLogger(TestIDBClient.class);

  private KnoxSession knoxSession;

  @BeforeClass
  public static void classSetup() throws Exception {
    Thread.currentThread().setName("JUnit");
  }

  @Test
  public void testCredentialsUserOnly() throws Exception {
  Configuration configuration = createUnitTestConfiguration();
//	    configuration.set(IDBConstants.IDBROKER_GATEWAY, "https://ctr-e139-1542663976389-22700-01-000003.hwx.site:8443/gateway/");
    configuration.set(IDBConstants.IDBROKER_ONLY_USER_METHOD, "true");
  knoxSession = KnoxSession.login(IDBTestUtils.getDefaultDTURL(),
          IDBTestUtils.TEST_ADMIN_USER,
          IDBTestUtils.TEST_ADMIN_PASS,
          null,
          null);

    IDBClient idbClient = mockIDBClient(configuration);
//    expect(idbClient.requestKnoxDelegationToken(knoxSession)).andReturn("sldhfhdslfhksdhfjkdhskh");
//    expect(idbClient.fetchAWSCredentials(knoxSession)).andReturn("Hello");
    //    EasyMock.expect(context.getInitParameter("knoxsso.cookie.name")).andReturn(null);

    String gateway = configuration.get(IDBConstants.IDBROKER_GATEWAY,
        IDBConstants.LOCAL_GATEWAY);
    LOG.info("Using gateway {}", gateway);

    assertEquals(IdentityBrokerClient.IDBMethod.USER_ONLY,
        idbClient.determineIDBMethodToCall());
    
    // TODO: add mocked calls to track that IDBClient actually calls the right methods
    
//	String knoxDT = idbClient
//        .requestKnoxDelegationToken(knoxSession).validate().access_token;
//    KnoxSession cloudSession = idbClient.cloudSessionFromDT(knoxDT);
//    MarshalledCredentials awsCredentials = 
//        idbClient.fetchAWSCredentials(cloudSession);
//    awsCredentials.validate("No creds",
//        MarshalledCredentials.CredentialTypeRequired.SessionOnly);

//    assertEquals("alice", parsedToken.getSubject());
//    assertTrue(authority.verifyToken(parsedToken));
  }
  
  @Test
  public void testCredentialsGroupsOnly() throws Exception {
  Configuration configuration = createUnitTestConfiguration();
    configuration.set(IDBConstants.IDBROKER_ONLY_GROUPS_METHOD, "true");
  knoxSession = KnoxSession.login(IDBTestUtils.getDefaultDTURL(),
          IDBTestUtils.TEST_ADMIN_USER,
          IDBTestUtils.TEST_ADMIN_PASS,
          null,
          null);

    IDBClient idbClient = mockIDBClient(configuration);

    String gateway = configuration.get(IDBConstants.IDBROKER_GATEWAY,
        IDBConstants.LOCAL_GATEWAY);
    LOG.info("Using gateway {}", gateway);

    assertEquals(IdentityBrokerClient.IDBMethod.GROUPS_ONLY,idbClient.determineIDBMethodToCall());

    // TODO: add mocked calls to track that IDBClient actually calls the right methods
  }

  @Test
  public void testCredentialsForSpecificGroup() throws Exception {
  Configuration configuration = createUnitTestConfiguration();
  configuration.set(IDBConstants.IDBROKER_SPECIFIC_GROUP_METHOD, "admin");
  knoxSession = KnoxSession.login(IDBTestUtils.getDefaultDTURL(),
          IDBTestUtils.TEST_ADMIN_USER,
          IDBTestUtils.TEST_ADMIN_PASS,
          null,
          null);

    IDBClient idbClient = mockIDBClient(configuration);

    String gateway = configuration.get(IDBConstants.IDBROKER_GATEWAY,
        IDBConstants.LOCAL_GATEWAY);
    LOG.info("Using gateway {}", gateway);

    assertEquals(IdentityBrokerClient.IDBMethod.SPECIFIC_GROUP,
        idbClient.determineIDBMethodToCall());

    // TODO: add mocked calls to track that IDBClient actually calls the right methods
  }

  private IDBClient mockIDBClient(final Configuration configuration)
      throws IOException {
    return EasyMock.partialMockBuilder(IDBClient.class)
        .withConstructor(Configuration.class, UserGroupInformation.class)
        .withArgs(configuration, UserGroupInformation.getCurrentUser())
        .addMockedMethods("requestKnoxDelegationToken")
        .addMockedMethods("fetchAWSCredentials")
        .addMockedMethods("cloudSessionFromDelegationToken")
        .addMockedMethods("cloudSessionFromDT")
        .createMock();
  }

  @Test
  public void testCredentialsForSpecificRole() throws Exception {
  Configuration configuration = createUnitTestConfiguration();
    configuration.set(IDBConstants.IDBROKER_SPECIFIC_ROLE_METHOD, "arn%3Aaws%3Aiam%3A%3A980678866538%3Arole%2Fstevel-s3guard");
  knoxSession = KnoxSession.login(IDBTestUtils.getDefaultDTURL(),
          IDBTestUtils.TEST_ADMIN_USER,
          IDBTestUtils.TEST_ADMIN_PASS,
          null,
          null);

    IDBClient idbClient = mockIDBClient(configuration);

    String gateway = configuration.get(IDBConstants.IDBROKER_GATEWAY,
        IDBConstants.LOCAL_GATEWAY);
    LOG.info("Using gateway {}", gateway);

    assertEquals(IdentityBrokerClient.IDBMethod.SPECIFIC_ROLE,
        idbClient.determineIDBMethodToCall());
  
    // TODO: add mocked calls to track that IDBClient actually calls the right methods
  }
}
