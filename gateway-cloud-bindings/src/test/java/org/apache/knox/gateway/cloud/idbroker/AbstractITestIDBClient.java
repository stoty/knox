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
import java.net.URI;

import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.test.HadoopTestBase;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.test.category.VerifyTest;

import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_GATEWAY;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

/**
 * Talk to the IDB client and request a DT for it.
 * This uses the username+pass login
 */
@Category(VerifyTest.class)
public abstract class AbstractITestIDBClient extends HadoopTestBase {

  protected static final Logger LOG =
      LoggerFactory.getLogger(AbstractITestIDBClient.class);

  private AbstractIDBClient idbClient;

  private KnoxSession knoxSession;

  public AbstractIDBClient getIdbClient() {
    return idbClient;
  }

  public KnoxSession getKnoxSession() {
    return knoxSession;
  }

  @Before
  public void setup() throws Throwable {
    Configuration configuration = createConfiguration();

    // Skip these tests if the expected configuration is not present
    assumeNotNull(configuration.get("fs.contract.test.fs.s3a"));

    String gateway = configuration.get(IDBROKER_GATEWAY.getPropertyName(), "");
    assumeTrue("No IDB gateway defined in + " + IDBROKER_GATEWAY,
        !gateway.isEmpty());
    LOG.info("Using gateway {}", gateway);
    idbClient = createIDBClient(configuration);
    knoxSession = createKnoxSession();
  }

  private Configuration createConfiguration() {
    return new Configuration();
  }

  /**
   * Create the IDB Client.
   * @param configuration configuration to use
   * @return an instantiated IDB Client.
   * @throws IOException failure
   */
  protected abstract AbstractIDBClient createIDBClient(Configuration configuration)
      throws IOException;

  protected abstract String getOrigin();

  /**
   * Create the Knox session;
   * will be invoked after {@link #createIDBClient(Configuration)}.
   * @return an instantiated Knox session
   * @throws IOException failure
   */
  protected abstract KnoxSession createKnoxSession() throws IOException;

  @Test
  public void testRequestKnoxToken() throws Throwable {
    RequestDTResponseMessage message
        = idbClient.requestKnoxDelegationToken(knoxSession, getOrigin(),
        new URI("s3a://something/"));
    message.validate();
    LOG.info("Access Token was issued {}", message.access_token);
  }

  @Test
  public void testRequestAWSFromKnoxToken() throws Throwable {
    RequestDTResponseMessage response = idbClient
        .requestKnoxDelegationToken(knoxSession,
            "( " + getOrigin() + ")", null)
        .validate();
    String knoxDT = response.access_token;
    CloudAccessBrokerSession cloudSession = idbClient.cloudSessionFromDT(
        knoxDT,
        response.endpoint_public_cert);
    MarshalledCredentials awsCredentials = 
        (MarshalledCredentials)idbClient.fetchCloudCredentials(cloudSession);
    awsCredentials.validate("No creds",
        MarshalledCredentials.CredentialTypeRequired.SessionOnly);
  }
}
