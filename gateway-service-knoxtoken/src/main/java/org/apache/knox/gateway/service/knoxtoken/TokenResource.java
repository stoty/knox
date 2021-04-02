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
package org.apache.knox.gateway.service.knoxtoken;

import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.inject.Singleton;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.binary.Base64;
import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.security.SubjectUtils;
import org.apache.knox.gateway.services.ServiceType;
import org.apache.knox.gateway.services.GatewayServices;
import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.KeystoreService;
import org.apache.knox.gateway.services.security.KeystoreServiceException;
import org.apache.knox.gateway.services.security.token.JWTokenAttributes;
import org.apache.knox.gateway.services.security.token.JWTokenAttributesBuilder;
import org.apache.knox.gateway.services.security.token.JWTokenAuthority;
import org.apache.knox.gateway.services.security.token.TokenMetadata;
import org.apache.knox.gateway.services.security.token.TokenServiceException;
import org.apache.knox.gateway.services.security.token.TokenStateService;
import org.apache.knox.gateway.services.security.token.TokenUtils;
import org.apache.knox.gateway.services.security.token.UnknownTokenException;
import org.apache.knox.gateway.services.security.token.impl.JWT;
import org.apache.knox.gateway.services.security.token.impl.JWTToken;
import org.apache.knox.gateway.util.JsonUtils;
import org.apache.knox.gateway.util.Tokens;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.MediaType.APPLICATION_XML;

@Singleton
@Path(TokenResource.RESOURCE_PATH)
public class TokenResource {
  private static final String LIFESPAN_DAYS = "lifespan";
  private static final String EXPIRES_IN = "expires_in";
  private static final String TOKEN_TYPE = "token_type";
  private static final String ACCESS_TOKEN = "access_token";
  private static final String TOKEN_ID = "token_id";
  private static final String MANAGED_TOKEN = "managed";
  private static final String TARGET_URL = "target_url";
  private static final String ENDPOINT_PUBLIC_CERT = "endpoint_public_cert";
  private static final String BEARER = "Bearer";
  private static final String TOKEN_TTL_PARAM = "knox.token.ttl";
  private static final String TOKEN_AUDIENCES_PARAM = "knox.token.audiences";
  private static final String TOKEN_TARGET_URL = "knox.token.target.url";
  private static final String TOKEN_CLIENT_DATA = "knox.token.client.data";
  private static final String TOKEN_CLIENT_CERT_REQUIRED = "knox.token.client.cert.required";
  private static final String TOKEN_ALLOWED_PRINCIPALS = "knox.token.allowed.principals";
  private static final String TOKEN_SIG_ALG = "knox.token.sigalg";
  private static final String TOKEN_EXP_RENEWAL_INTERVAL = "knox.token.exp.renew-interval";
  private static final String TOKEN_EXP_RENEWAL_MAX_LIFETIME = "knox.token.exp.max-lifetime";
  private static final String TOKEN_RENEWER_WHITELIST = "knox.token.renewer.whitelist";
  private static final long TOKEN_TTL_DEFAULT = 30000L;
  static final String RESOURCE_PATH = "knoxtoken/api/v1/token";
  static final String RENEW_PATH = "/renew";
  static final String REVOKE_PATH = "/revoke";
  static final String MARK_UNUSED_PATH = "/markUnused";
  private static final String TARGET_ENDPOINT_PULIC_CERT_PEM = "knox.token.target.endpoint.cert.pem";
  private static final long MILLIS_IN_DAY = 86400000L;
  private static TokenServiceMessages log = MessagesFactory.get(TokenServiceMessages.class);
  private long tokenTTL = TOKEN_TTL_DEFAULT;
  private List<String> targetAudiences = new ArrayList<>();
  private String tokenTargetUrl;
  private Map<String, Object> tokenClientDataMap;
  private List<String> allowedDNs = new ArrayList<>();
  private boolean clientCertRequired;
  private String signatureAlgorithm;
  private String endpointPublicCert;

  // Optional token store service
  private TokenStateService tokenStateService;

  private Optional<Long> renewInterval = Optional.empty();

  private Optional<Long> maxTokenLifetime = Optional.empty();

  private List<String> allowedRenewers;

  @Context
  HttpServletRequest request;

  @Context
  ServletContext context;

  @PostConstruct
  public void init() throws AliasServiceException {

    String audiences = context.getInitParameter(TOKEN_AUDIENCES_PARAM);
    if (audiences != null) {
      String[] auds = audiences.split(",");
      for (String aud : auds) {
        targetAudiences.add(aud.trim());
      }
    }

    String clientCert = context.getInitParameter(TOKEN_CLIENT_CERT_REQUIRED);
    clientCertRequired = "true".equals(clientCert);

    String principals = context.getInitParameter(TOKEN_ALLOWED_PRINCIPALS);
    if (principals != null) {
      String[] dns = principals.split(";");
      for (String dn : dns) {
        allowedDNs.add(dn.replaceAll("\\s+", ""));
      }
    }

    String ttl = context.getInitParameter(TOKEN_TTL_PARAM);
    if (ttl != null) {
      try {
        tokenTTL = Long.parseLong(ttl);
        if (tokenTTL < -1 || (tokenTTL + System.currentTimeMillis() < 0)) {
          log.invalidTokenTTLEncountered(ttl);
          tokenTTL = TOKEN_TTL_DEFAULT;
        }
      } catch (NumberFormatException nfe) {
        log.invalidTokenTTLEncountered(ttl);
      }
    }

    tokenTargetUrl = context.getInitParameter(TOKEN_TARGET_URL);

    String clientData = context.getInitParameter(TOKEN_CLIENT_DATA);
    if (clientData != null) {
      tokenClientDataMap = new HashMap<>();
      String[] tokenClientData = clientData.split(",");
      addClientDataToMap(tokenClientData, tokenClientDataMap);
    }

    setSignatureAlogrithm();

    String targetEndpointPublicCert = context.getInitParameter(TARGET_ENDPOINT_PULIC_CERT_PEM);
    if (targetEndpointPublicCert != null) {
      endpointPublicCert = targetEndpointPublicCert;
    }

    // If server-managed token expiration is configured, set the token state service
    if (isServerManagedTokenStateEnabled()) {
      String topologyName = getTopologyName();
      log.serverManagedTokenStateEnabled(topologyName);

      GatewayServices services = (GatewayServices) context.getAttribute(GatewayServices.GATEWAY_SERVICES_ATTRIBUTE);
      tokenStateService = services.getService(ServiceType.TOKEN_STATE_SERVICE);

      String renewIntervalValue = context.getInitParameter(TOKEN_EXP_RENEWAL_INTERVAL);
      if (renewIntervalValue != null && !renewIntervalValue.isEmpty()) {
        try {
          renewInterval = Optional.of(Long.parseLong(renewIntervalValue));
        } catch (NumberFormatException e) {
          log.invalidConfigValue(topologyName, TOKEN_EXP_RENEWAL_INTERVAL, renewIntervalValue, e);
        }
      }

      String maxLifetimeValue = context.getInitParameter(TOKEN_EXP_RENEWAL_MAX_LIFETIME);
      if (maxLifetimeValue != null && !maxLifetimeValue.isEmpty()) {
        try {
          maxTokenLifetime = Optional.of(Long.parseLong(maxLifetimeValue));
        } catch (NumberFormatException e) {
          log.invalidConfigValue(topologyName, TOKEN_EXP_RENEWAL_MAX_LIFETIME, maxLifetimeValue, e);
        }
      }

      allowedRenewers = new ArrayList<>();
      String renewerList = context.getInitParameter(TOKEN_RENEWER_WHITELIST);
      if (renewerList != null && !renewerList.isEmpty()) {
        for (String renewer : renewerList.split(",")) {
          allowedRenewers.add(renewer.trim());
        }
      } else {
        log.noRenewersConfigured(topologyName);
      }
    }
  }

  private void setSignatureAlogrithm() throws AliasServiceException {
    final String configuredSigAlg = context.getInitParameter(TOKEN_SIG_ALG);
    final GatewayConfig config = (GatewayConfig) request.getServletContext().getAttribute(GatewayConfig.GATEWAY_CONFIG_ATTRIBUTE);
    final GatewayServices services = (GatewayServices) request.getServletContext().getAttribute(GatewayServices.GATEWAY_SERVICES_ATTRIBUTE);
    signatureAlgorithm = TokenUtils.getSignatureAlgorithm(configuredSigAlg, (AliasService) services.getService(ServiceType.ALIAS_SERVICE), config.getSigningKeystoreName());
  }

  private boolean isServerManagedTokenStateEnabled() {
    boolean isServerManaged;

    // First, check for explicit service-level configuration
    String serviceParamValue = context.getInitParameter(TokenStateService.CONFIG_SERVER_MANAGED);

    // If there is no service-level configuration
    if (serviceParamValue == null || serviceParamValue.isEmpty()) {
      // Fall back to the gateway-level default
      GatewayConfig config = (GatewayConfig) context.getAttribute(GatewayConfig.GATEWAY_CONFIG_ATTRIBUTE);
      isServerManaged = (config != null) && config.isServerManagedTokenStateEnabled();
    } else {
      // Otherwise, apply the service-level configuration
      isServerManaged = Boolean.valueOf(serviceParamValue);
    }

    return isServerManaged;
  }

  @GET
  @Produces({APPLICATION_JSON, APPLICATION_XML})
  public Response doGet() {
    return getAuthenticationToken();
  }

  @POST
  @Produces({APPLICATION_JSON, APPLICATION_XML})
  public Response doPost() {
    return getAuthenticationToken();
  }

  @POST
  @Path(RENEW_PATH)
  @Produces({APPLICATION_JSON})
  public Response renew(String token) {
    Response resp;

    long expiration = 0;

    String          error       = "";
    Response.Status errorStatus = Response.Status.BAD_REQUEST;

    if (tokenStateService == null) {
      // If the token state service is disabled, then return the expiration from the specified token
      try {
        JWTToken jwt = new JWTToken(token);
        log.renewalDisabled(getTopologyName(), Tokens.getTokenDisplayText(token), TokenUtils.getTokenId(jwt));
        expiration = Long.parseLong(jwt.getExpires());
      } catch (ParseException e) {
        log.invalidToken(getTopologyName(), Tokens.getTokenDisplayText(token), e);
        error = safeGetMessage(e);
      } catch (Exception e) {
        error = safeGetMessage(e);
      }
    } else {
      String renewer = SubjectUtils.getCurrentEffectivePrincipalName();
      if (allowedRenewers.contains(renewer)) {
        try {
          JWTToken jwt = new JWTToken(token);
          // If renewal fails, it should be an exception
          expiration = tokenStateService.renewToken(jwt,
                                                    renewInterval.orElse(tokenStateService.getDefaultRenewInterval()));
          log.renewedToken(getTopologyName(),
                           Tokens.getTokenDisplayText(token),
                           TokenUtils.getTokenId(jwt),
                           renewer);
        } catch (ParseException e) {
          log.invalidToken(getTopologyName(), Tokens.getTokenDisplayText(token), e);
          error = safeGetMessage(e);
        } catch (Exception e) {
          error = safeGetMessage(e);
        }
      } else {
        errorStatus = Response.Status.FORBIDDEN;
        error = "Caller (" + renewer + ") not authorized to renew tokens.";
      }
    }

    if(error.isEmpty()) {
      resp =  Response.status(Response.Status.OK)
                      .entity("{\n  \"renewed\": \"true\",\n  \"expires\": \"" + expiration + "\"\n}\n")
                      .build();
    } else {
      log.badRenewalRequest(getTopologyName(), Tokens.getTokenDisplayText(token), error);
      resp = Response.status(errorStatus)
                     .entity("{\n  \"renewed\": \"false\",\n  \"error\": \"" + error + "\"\n}\n")
                     .build();
    }

    return resp;
  }

  @POST
  @Path(REVOKE_PATH)
  @Produces({APPLICATION_JSON})
  public Response revoke(String token) {
    Response resp;

    String          error       = "";
    Response.Status errorStatus = Response.Status.BAD_REQUEST;

    if (tokenStateService == null) {
      error = "Token revocation support is not configured";
    } else {
      String renewer = SubjectUtils.getCurrentEffectivePrincipalName();
      if (allowedRenewers.contains(renewer)) {
        try {
          JWTToken jwt = new JWTToken(token);
          tokenStateService.revokeToken(jwt);
          log.revokedToken(getTopologyName(), Tokens.getTokenDisplayText(token), TokenUtils.getTokenId(jwt), renewer);
        } catch (ParseException e) {
          log.invalidToken(getTopologyName(), Tokens.getTokenDisplayText(token), e);
          error = safeGetMessage(e);
        } catch (UnknownTokenException e) {
          error = safeGetMessage(e);
        }
      } else {
        errorStatus = Response.Status.FORBIDDEN;
        error = "Caller (" + renewer + ") not authorized to revoke tokens.";
      }
    }

    if (error.isEmpty()) {
      resp =  Response.status(Response.Status.OK)
                      .entity("{\n  \"revoked\": \"true\"\n}\n")
                      .build();
    } else {
      log.badRevocationRequest(getTopologyName(), Tokens.getTokenDisplayText(token), error);
      resp = Response.status(errorStatus)
                     .entity("{\n  \"revoked\": \"false\",\n  \"error\": \"" + error + "\"\n}\n")
                     .build();
    }

    return resp;
  }

  @POST
  @Path(MARK_UNUSED_PATH)
  @Produces({ APPLICATION_JSON })
  @Deprecated
  public Response markUnused(String token) {
    //to be backward compatible we return SUCCESS status if cloud bindings code in older DH is trying to invoke this API
    return Response.status(Response.Status.OK).entity("{\n  \"markedUnused\": \"true\"\n}\n").build();
  }

  private X509Certificate extractCertificate(HttpServletRequest req) {
    X509Certificate[] certs = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
    if (null != certs && certs.length > 0) {
      return certs[0];
    }
    return null;
  }

  private Response getAuthenticationToken() {
    if (clientCertRequired) {
      X509Certificate cert = extractCertificate(request);
      if (cert != null) {
        if (!allowedDNs.contains(cert.getSubjectDN().getName().replaceAll("\\s+", ""))) {
          return Response.status(Response.Status.FORBIDDEN)
                         .entity("{ \"Unable to get token - untrusted client cert.\" }")
                         .build();
        }
      } else {
        return Response.status(Response.Status.FORBIDDEN)
                       .entity("{ \"Unable to get token - client cert required.\" }")
                       .build();
      }
    }
    GatewayServices services = (GatewayServices) request.getServletContext()
        .getAttribute(GatewayServices.GATEWAY_SERVICES_ATTRIBUTE);

    JWTokenAuthority ts = services.getService(ServiceType.TOKEN_SERVICE);
    Principal p = request.getUserPrincipal();
    long expires = getExpiry();

    if (endpointPublicCert == null) {
      // acquire PEM for gateway identity of this gateway instance
      KeystoreService ks = services.getService(ServiceType.KEYSTORE_SERVICE);
      if (ks != null) {
        try {
          Certificate cert = ks.getCertificateForGateway();
          byte[] bytes = cert.getEncoded();
          //Base64 encoder = new Base64(76, "\n".getBytes("ASCII"));
          endpointPublicCert = Base64.encodeBase64String(bytes);
        } catch (KeyStoreException | KeystoreServiceException | CertificateEncodingException e) {
          // assuming that certs will be properly provisioned across all clients
          log.unableToAcquireCertForEndpointClients(e);
        }
      }
    }

    try {
      final boolean managedToken = tokenStateService != null;
      JWT token;
      JWTokenAttributes jwtAttributes;
      if (targetAudiences.isEmpty()) {
        jwtAttributes = new JWTokenAttributesBuilder().setPrincipal(p).setAlgorithm(signatureAlgorithm).setExpires(expires).setManaged(managedToken).build();
        token = ts.issueToken(jwtAttributes);
      } else {
        jwtAttributes = new JWTokenAttributesBuilder().setPrincipal(p).setAudiences(targetAudiences).setAlgorithm(signatureAlgorithm).setExpires(expires)
            .setManaged(managedToken).build();
        token = ts.issueToken(jwtAttributes);
      }

      if (token != null) {
        String accessToken = token.toString();
        String tokenId = TokenUtils.getTokenId(token);
        log.issuedToken(getTopologyName(), Tokens.getTokenDisplayText(accessToken), tokenId);

        HashMap<String, Object> map = new HashMap<>();
        map.put(ACCESS_TOKEN, accessToken);
        map.put(TOKEN_ID, tokenId);
        map.put(MANAGED_TOKEN, String.valueOf(managedToken));
        map.put(TOKEN_TYPE, BEARER);
        map.put(EXPIRES_IN, expires);
        if (tokenTargetUrl != null) {
          map.put(TARGET_URL, tokenTargetUrl);
        }
        if (tokenClientDataMap != null) {
          map.putAll(tokenClientDataMap);
        }
        if (endpointPublicCert != null) {
          map.put(ENDPOINT_PUBLIC_CERT, endpointPublicCert);
        }

        String jsonResponse = JsonUtils.renderAsJsonString(map);

        // Optional token store service persistence
        if (tokenStateService != null) {
          tokenStateService.addToken(tokenId,
                                     System.currentTimeMillis(),
                                     expires,
                                     maxTokenLifetime.orElse(tokenStateService.getDefaultMaxLifetimeDuration()));
          tokenStateService.addMetadata(tokenId, new TokenMetadata(p.getName()));
          log.storedToken(getTopologyName(), Tokens.getTokenDisplayText(accessToken), tokenId);
        }

        return Response.ok().entity(jsonResponse).build();
      } else {
        return Response.serverError().build();
      }
    } catch (TokenServiceException e) {
      log.unableToIssueToken(e);
    }
    return Response.ok().entity("{ \"Unable to acquire token.\" }").build();
  }

  void addClientDataToMap(String[] tokenClientData,
      Map<String,Object> map) {
    String[] kv;
    for (String tokenClientDatum : tokenClientData) {
      kv = tokenClientDatum.split("=");
      if (kv.length == 2) {
        map.put(kv[0], kv[1]);
      }
    }
  }

  private long getExpiry() {
    long expiry = 0L;
    long millis = 0L;

    String lifetimeStr = request.getParameter(LIFESPAN_DAYS);
    if (lifetimeStr == null || lifetimeStr.isEmpty()) {
      if (tokenTTL == -1) {
        return -1;
      }
      millis = tokenTTL;
    }
    else {
      try {
        // lifetime is in days
        long lifetime = Long.parseLong(lifetimeStr);
        if (lifetime * MILLIS_IN_DAY <= tokenTTL) {
          millis = lifetime * MILLIS_IN_DAY;
        }
      }
      catch (NumberFormatException e) {
        log.invalidLifetimeValue(lifetimeStr);
        millis = tokenTTL;
      }
    }
    expiry = System.currentTimeMillis() + millis;

    return expiry;
  }

  private String getTopologyName() {
    return (String) context.getAttribute("org.apache.knox.gateway.gateway.cluster");
  }

  /**
   * Safely get the message from the specified Throwable.
   *
   * @param t A Throwable
   * @return The result of t.getMessage(), or &quot;null&quot; if that result is null.
   */
  private String safeGetMessage(Throwable t) {
    String message = t.getMessage();
    return message != null ? message : "null";
  }

}
