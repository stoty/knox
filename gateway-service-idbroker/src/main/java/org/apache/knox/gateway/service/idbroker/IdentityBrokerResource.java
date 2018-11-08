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
package org.apache.knox.gateway.service.idbroker;

import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.services.GatewayServices;
import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.CryptoService;

import javax.annotation.PostConstruct;
import javax.inject.Singleton;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Properties;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

@Singleton
@Path(IdentityBrokerResource.RESOURCE_PATH)
public class IdentityBrokerResource {
  private static final String CREDENTIALS_API_PATH = "credentials";
  private static final String USER_CREDENTIALS_API_PATH = CREDENTIALS_API_PATH + "/user";

  private static final String GROUP_CREDENTIALS_API_PATH = CREDENTIALS_API_PATH + "/group";
  private static final String EXPLICIT_GROUP_CREDENTIALS_API_PATH = GROUP_CREDENTIALS_API_PATH + "/{id}";

  private static final String ROLE_CREDENTIALS_API_PATH = CREDENTIALS_API_PATH + "/role";
  private static final String EXPLICIT_ROLE_CREDENTIALS_API_PATH = ROLE_CREDENTIALS_API_PATH + "/{id}";

  private static IdBrokerServiceMessages log = MessagesFactory.get(IdBrokerServiceMessages.class);

  private static final String VERSION_TAG = "api/v1";
  static final String RESOURCE_PATH = "/cab/" + VERSION_TAG;

  private static final String CONTENT_TYPE = "application/json";
  private static final String CACHE_CONTROL = "Cache-Control";
  private static final String NO_CACHE = "must-revalidate,no-cache,no-store";

  /**
   * Alias for password used to encrypt cloud credential cache.
   */
  public static final String CREDENTIAL_CACHE_ALIAS = "credentialCacheAlias";

  // TODO: Reference shared constants for these
  private static final String ROLE_TYPE_USER     = "USER_ROLE";
  private static final String ROLE_TYPE_GROUP    = "GROUP_ROLE";
  private static final String ROLE_TYPE_EXPLICIT = "EXPLICIT_ROLE";

  private CloudClientConfigurationProvider configProvider = new CloudClientConfigurationProviderManager();
  private KnoxCloudCredentialsClient credentialsClient = new KnoxCloudCredentialsClientManager();

  @Context
  HttpServletRequest request;

  @Context
  ServletContext context;

  @PostConstruct
  public void init() {
    Properties props = getProperties();
    String topologyName = (String) request.getServletContext().getAttribute(GatewayServices.GATEWAY_CLUSTER_ATTRIBUTE);
    props.setProperty("topology.name", topologyName);

    /**
     * we don't want to overwrite an existing alias from a previous topology deployment
     * so we can't just blindly generateAlias here.
     * this version of getPassword will generate a value for it only if missing
    **/
    final AliasService aliasService = getAliasService();
    try {
      aliasService.getPasswordFromAliasForCluster(topologyName, CREDENTIAL_CACHE_ALIAS, true);
    } catch (AliasServiceException e) {
      e.printStackTrace();
    }

    configProvider.init(props);
    credentialsClient.init(props);
    credentialsClient.setConfigProvider(configProvider);
    credentialsClient.setAliasService(aliasService);
    credentialsClient.setCryptoService(getCryptoService());
  }

  private AliasService getAliasService() {
    GatewayServices services = (GatewayServices) request.getServletContext()
        .getAttribute(GatewayServices.GATEWAY_SERVICES_ATTRIBUTE);
    return services.getService(GatewayServices.ALIAS_SERVICE);
  }

  private CryptoService getCryptoService() {
    GatewayServices services = (GatewayServices) request.getServletContext()
        .getAttribute(GatewayServices.GATEWAY_SERVICES_ATTRIBUTE);
    return services.getService(GatewayServices.CRYPTO_SERVICE);
  }

  private Properties getProperties() {
    Properties props = new Properties();

    String paramName;
    Enumeration<String> e = context.getInitParameterNames();
    while (e.hasMoreElements()) {
      paramName = e.nextElement();
      props.setProperty(paramName, context.getInitParameter(paramName));
    }

    return props;
  }

  @GET
  @Produces({APPLICATION_JSON})
  @Path(CREDENTIALS_API_PATH)
  public Response getCredentials() {
    return getCredentialsResponse();
  }

  @GET
  @Produces({APPLICATION_JSON})
  @Path(USER_CREDENTIALS_API_PATH)
  public Response getCredentialsForUserRole() {
    return getCredentialsResponse(ROLE_TYPE_USER, null);
  }

  @GET
  @Produces({APPLICATION_JSON})
  @Path(GROUP_CREDENTIALS_API_PATH)
  public Response getCredentialsForGroupRole() {
    return getCredentialsForGroupRole(null);
  }

  @GET
  @Produces({APPLICATION_JSON})
  @Path(EXPLICIT_GROUP_CREDENTIALS_API_PATH)
  public Response getCredentialsForGroupRole(@PathParam("id") String group) {
    return getCredentialsResponse(ROLE_TYPE_GROUP, group);
  }

  @GET
  @Produces({APPLICATION_JSON})
  @Path(EXPLICIT_ROLE_CREDENTIALS_API_PATH)
  public Response getCredentialsForRole(@PathParam("id") String role) {
    return getCredentialsResponse(ROLE_TYPE_EXPLICIT, role);
  }

  private Response getCredentialsResponse() {
    return getCredentialsResponse("");
  }

  private Response getCredentialsResponse(String roleType) {
    return getCredentialsResponse(roleType, null);
  }

  private Response getCredentialsResponse(String roleType, String id) {
    Response response = null;

    try {
      String credentialsResponse = getRoleCredentialsResponse(roleType, id);
      response = Response.ok().entity(credentialsResponse).build();
    } catch (WebApplicationException e) {
      log.logException(e);
      response = e.getResponse();
    } catch (Exception e) {
      log.logException(e);
      response = Response.serverError()
                         .entity(String.format(Locale.getDefault(), "{ \"error\": \"Could not acquire credentials due to : %s\"", e))
                         .build();
    }

    return response;
  }


  private String getRoleCredentialsResponse(String roleType, String id) {
    Object creds = credentialsClient.getCredentialsForRole(roleType, id);
    return creds.toString();
  }

}
