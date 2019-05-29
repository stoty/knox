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

import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;

import java.io.IOException;
import java.net.URI;

public interface IDBClient<CloudCredentialType> {

  enum IDBMethod {
    DEFAULT, GROUPS_ONLY, SPECIFIC_GROUP, USER_ONLY, SPECIFIC_ROLE
  }

  /**
   * @return The base URL for the active Cloud Access Broker endpoint.
   */
  String getGatewayAddress();

  /**
   * Login to the IDBroker using the configured authentication mechanism - basic-auth or Kerberos
   *
   * @param configuration the configuration data
   * @return a {@link Pair} containing the {@link KnoxSession} and the session's origin value
   * @throws IOException
   */
  Pair<KnoxSession, String> login(Configuration configuration) throws IOException;

  /**
   * Build some credentials from the response.
   *
   * @param basicResponse the response to parse
   * @return the retrieved credentials
   * @throws IOException failure
   */
  CloudCredentialType extractCloudCredentialsFromResponse(BasicResponse basicResponse) throws IOException;

  /**
   * Create cloud session from the delegation token information.
   * Only valid from a full Client instance.
   *
   * @param delegationToken token as extracted from a DT.
   * @param endpointCert
   * @throws IOException failure.
   */
  KnoxSession cloudSessionFromDT(String delegationToken, final String endpointCert) throws IOException;


  /**
   * Create cloud session from the delegation token information.
   * Only valid from a full Client instance.
   *
   * This assumes the delegation token is a Bearer token.
   *
   * @param delegationToken token as extracted from a DT.
   * @param endpointCert
   * @throws IOException failure.
   */
  CloudAccessBrokerSession cloudSessionFromDelegationToken(String delegationToken,
                                                           String endpointCert)
      throws IOException;

  /**
   * Create cloud session from the delegation token information.
   * Only valid from a full Client instance.
   *
   * @param delegationToken token as extracted from a delegation token.
   * @param delegationTokenType The type of the token
   * @param endpointCert The certificate for the endpoint, which can be used to override or augment the configured
   *                     trust store contents.
   * @throws IOException failure.
   */
  CloudAccessBrokerSession cloudSessionFromDelegationToken(String delegationToken,
                                                           String delegationTokenType,
                                                           String endpointCert)
      throws IOException;

  /**
   * Fetch the cloud credentials.
   *
   * @param session Knox session
   * @return the credentials.
   * @throws IOException failure
   */
  CloudCredentialType fetchCloudCredentials(CloudAccessBrokerSession session) throws IOException;

  /**
   * Determine the IDBMethod to call based on config params
   *
   * @return the method
   */
  IDBMethod determineIDBMethodToCall();

  /**
   * Ask for a delegation token.
   *
   * @param dtSession session
   * @param origin
   * @param fsUri
   * @return the delegation token response
   * @throws IOException failure.
   */
  RequestDTResponseMessage requestKnoxDelegationToken(KnoxSession dtSession,
                                                      final String origin,
                                                      final URI fsUri) throws IOException;

  /**
   * Update a still-valid delegation token, using only the delegation token for authentication.
   *
   * @param delegationToken The existing valid Knox token.
   * @param delegationTokenType The type of the valid Knox token.
   * @param cabPublicCert Optional Knox gateway certificate from the existing delegation token, for establishing trust.
   *
   * @return The delegation token response.
   */
  RequestDTResponseMessage updateDelegationToken(final String delegationToken,
                                                 final String delegationTokenType,
                                                 final String cabPublicCert) throws Exception;

}
