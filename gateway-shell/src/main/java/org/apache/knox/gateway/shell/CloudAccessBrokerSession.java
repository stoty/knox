/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.knox.gateway.shell;

import java.net.URISyntaxException;
import java.util.Map;

/**
 * A KnoxSession extension for
 */
public class CloudAccessBrokerSession extends KnoxSession {

  // Keep the context around so the session client can be updated later
  private ClientContext clientContext;

  CloudAccessBrokerSession(final ClientContext clientContext) throws URISyntaxException {
    super(clientContext);
    this.clientContext = clientContext;
  }

  public void updateEndpoint(final String endpoint, final String authToken) throws Exception {
    base = endpoint;

    ClientContext updated =
      ClientContext.with(endpoint)
                   .withSubjectCredsOnly(clientContext.useSubjectCredsOnly())
                   .connection().withTruststore(clientContext.connection().truststoreLocation(),
                                                clientContext.connection().truststorePass())
                                .withPublicCertPem(clientContext.connection().endpointPublicCertPem())
                                .end()
                   .kerberos().enable(clientContext.kerberos().enable())
                              .debug(clientContext.kerberos().debug())
                              .jaasConf(clientContext.kerberos().jaasConf())
                              .krb5Conf(clientContext.kerberos().krb5Conf())
                              .end();

    if (authToken != null) {
      String previousAuthToken = headers.remove("Authorization");
      String tokenType =
          (previousAuthToken != null) ? previousAuthToken.substring(0, previousAuthToken.indexOf(" ")) : "Bearer";
      headers.put("Authorization", tokenType + " " + authToken);
    }

    // Update the client based on the context with the updated endpoint
    client = createClient(updated);
  }

  public static CloudAccessBrokerSession create(String url, Map<String, String> headers) throws URISyntaxException {
    CloudAccessBrokerSession instance = new CloudAccessBrokerSession(ClientContext.with(url));
    instance.setHeaders(headers);
    return instance;
  }

  public static CloudAccessBrokerSession create(String             url,
                                                Map<String,String> headers,
                                                String             truststoreLocation,
                                                String             truststorePass) throws URISyntaxException {
    CloudAccessBrokerSession instance =
        new CloudAccessBrokerSession(ClientContext.with(url)
                                                  .connection()
                                                  .withTruststore(truststoreLocation, truststorePass)
                                                  .end());
    instance.setHeaders(headers);
    return instance;
  }

  public static CloudAccessBrokerSession create(String url,
                                                String username,
                                                String password) throws URISyntaxException {
    return new CloudAccessBrokerSession(ClientContext.with(username, password, url));
  }

  public static CloudAccessBrokerSession create(String url,
                                                String username,
                                                String password,
                                                String truststoreLocation,
                                                String truststorePass) throws URISyntaxException {

    return new CloudAccessBrokerSession(ClientContext.with(username, password, url)
                                                     .connection()
                                                     .withTruststore(truststoreLocation, truststorePass)
                                                     .end());
  }

  public static CloudAccessBrokerSession create(ClientContext context) throws URISyntaxException {
    return new CloudAccessBrokerSession(context);
  }

}
