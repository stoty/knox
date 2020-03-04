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
package org.apache.knox.gateway.config;

import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface GatewayConfig {

  // Used as the basis for any home directory that is not specified.
  String GATEWAY_HOME_VAR = "GATEWAY_HOME";

  /**
   * Variable name for the location of configuration files edited by users
   *
   * @deprecated use {@link GatewayConfig#KNOX_GATEWAY_CONF_DIR_VAR} instead
   */
  String GATEWAY_CONF_HOME_VAR = "GATEWAY_CONF_HOME";

  String KNOX_GATEWAY_CONF_DIR_VAR = "KNOX_GATEWAY_CONF_DIR";

  /**
   * Variable name for the location of data files generated by the gateway at runtime.
   *
   * @deprecated use {@link GatewayConfig#KNOX_GATEWAY_DATA_DIR} instead
   */
  String GATEWAY_DATA_HOME_VAR = "GATEWAY_DATA_HOME";

  String KNOX_GATEWAY_DATA_DIR = "KNOX_GATEWAY_DATA_DIR";

  String GATEWAY_CONFIG_ATTRIBUTE = "org.apache.knox.gateway.config";
  String HADOOP_KERBEROS_SECURED = "gateway.hadoop.kerberos.secured";
  String KRB5_CONFIG = "java.security.krb5.conf";
  String KRB5_DEBUG = "sun.security.krb5.debug";
  String KRB5_LOGIN_CONFIG = "java.security.auth.login.config";
  String KRB5_USE_SUBJECT_CREDS_ONLY = "javax.security.auth.useSubjectCredsOnly";

  String IDENTITY_KEYSTORE_PASSWORD_ALIAS = "gateway.tls.keystore.password.alias";
  String IDENTITY_KEYSTORE_PATH = "gateway.tls.keystore.path";
  String IDENTITY_KEYSTORE_TYPE = "gateway.tls.keystore.type";
  String IDENTITY_KEY_ALIAS = "gateway.tls.key.alias";
  String IDENTITY_KEY_PASSPHRASE_ALIAS = "gateway.tls.key.passphrase.alias";
  String DEFAULT_IDENTITY_KEYSTORE_TYPE = "JKS";
  String DEFAULT_IDENTITY_KEYSTORE_PASSWORD_ALIAS = "gateway-identity-keystore-password";
  String DEFAULT_IDENTITY_KEY_ALIAS = "gateway-identity";
  String DEFAULT_IDENTITY_KEY_PASSPHRASE_ALIAS = "gateway-identity-passphrase";
  String DEFAULT_GATEWAY_KEYSTORE_NAME = "gateway.jks";

  String SIGNING_KEYSTORE_NAME = "gateway.signing.keystore.name";
  String SIGNING_KEYSTORE_PASSWORD_ALIAS = "gateway.signing.keystore.password.alias";
  String SIGNING_KEYSTORE_TYPE = "gateway.signing.keystore.type";
  String SIGNING_KEY_ALIAS = "gateway.signing.key.alias";
  String SIGNING_KEY_PASSPHRASE_ALIAS = "gateway.signing.key.passphrase.alias";
  String DEFAULT_SIGNING_KEYSTORE_PASSWORD_ALIAS = "signing.keystore.password";
  String DEFAULT_SIGNING_KEYSTORE_TYPE = "JKS";
  String DEFAULT_SIGNING_KEY_ALIAS = "gateway-identity";
  String DEFAULT_SIGNING_KEY_PASSPHRASE_ALIAS = "signing.key.passphrase";

  String GATEWAY_TRUSTSTORE_PASSWORD_ALIAS = "gateway.truststore.password.alias";
  String GATEWAY_TRUSTSTORE_PATH = "gateway.truststore.path";
  String GATEWAY_TRUSTSTORE_TYPE = "gateway.truststore.type";
  String DEFAULT_GATEWAY_TRUSTSTORE_TYPE = "JKS";
  String DEFAULT_GATEWAY_TRUSTSTORE_PASSWORD_ALIAS = "gateway-truststore-password";

  String HTTP_CLIENT_TRUSTSTORE_PASSWORD_ALIAS = "gateway.httpclient.truststore.password.alias";
  String HTTP_CLIENT_TRUSTSTORE_PATH = "gateway.httpclient.truststore.path";
  String HTTP_CLIENT_TRUSTSTORE_TYPE = "gateway.httpclient.truststore.type";
  String DEFAULT_HTTP_CLIENT_TRUSTSTORE_TYPE = "JKS";
  String DEFAULT_HTTP_CLIENT_TRUSTSTORE_PASSWORD_ALIAS = "gateway-httpclient-truststore-password";

  String REMOTE_CONFIG_REGISTRY_TYPE = "type";
  String REMOTE_CONFIG_REGISTRY_ADDRESS = "address";
  String REMOTE_CONFIG_REGISTRY_NAMESPACE = "namespace";
  String REMOTE_CONFIG_REGISTRY_AUTH_TYPE = "authType";
  String REMOTE_CONFIG_REGISTRY_PRINCIPAL = "principal";
  String REMOTE_CONFIG_REGISTRY_CREDENTIAL_ALIAS = "credentialAlias";
  String REMOTE_CONFIG_REGISTRY_KEYTAB = "keytab";
  String REMOTE_CONFIG_REGISTRY_USE_KEYTAB = "useKeytab";
  String REMOTE_CONFIG_REGISTRY_USE_TICKET_CACHE = "useTicketCache";

  String PROXYUSER_SERVICES_IGNORE_DOAS = "gateway.proxyuser.services.ignore.doas";

  /**
   * The location of the gateway configuration.
   * Subdirectories will be: topologies
   * @return The location of the gateway configuration.
   */
  String getGatewayConfDir();

  /**
   * The location of the gateway runtime generated data.
   * Subdirectories will be security, deployments
   * @return The location of the gateway runtime generated data.
   */
  String getGatewayDataDir();

  /**
   * The location of the gateway services definition's root directory
   * @return The location of the gateway services top level directory.
   */
  String getGatewayServicesDir();

  /**
   * The location of the gateway applications's root directory
   * @return The location of the gateway applications top level directory.
   */
  String getGatewayApplicationsDir();

  String getHadoopConfDir();

  String getGatewayHost();

  int getGatewayPort();

  String getGatewayPath();

  String getGatewayProvidersConfigDir();

  String getGatewayDescriptorsDir();

  String getGatewayTopologyDir();

  String getGatewaySecurityDir();

  /**
   * Returns the path to the Gateway's keystore directory
   * <p>
   * This path is generally calculated to be a subdirectory named "keystores" under the configured
   * "security" directory. However, it may be possible for it to be configured as something else.
   *
   * @return the path to the Gateway's keystore directory
   */
  String getGatewayKeystoreDir();

  String getGatewayDeploymentDir();

  InetSocketAddress getGatewayAddress() throws UnknownHostException;

  boolean isSSLEnabled();

  List<String> getExcludedSSLProtocols();

  List<String> getIncludedSSLCiphers();

  List<String> getExcludedSSLCiphers();

  boolean isHadoopKerberosSecured();

  String getKerberosConfig();

  boolean isKerberosDebugEnabled();

  String getKerberosLoginConfig();

  String getDefaultTopologyName();

  String getDefaultAppRedirectPath();

  String getFrontendUrl();

  boolean isClientAuthNeeded();

  boolean isClientAuthWanted();

  String getTruststorePath();

  boolean getTrustAllCerts();

  String getKeystoreType();

  String getTruststoreType();

  /**
   * Returns the configured value for the alias name to use when to looking up the Gateway's
   * truststore password.
   *
   * @return an alias name
   */
  String getTruststorePasswordAlias();

  boolean isXForwardedEnabled();

  String getEphemeralDHKeySize();

  int getHttpClientMaxConnections();

  int getHttpClientConnectionTimeout();

  int getHttpClientSocketTimeout();

  /**
   * Returns the configured value for the path to the truststore to be used by the HTTP client instance
   * connecting to a service from the Gateway.
   *
   * @return a path to the trust file; or <code>null</code> if not set
   */
  String getHttpClientTruststorePath();

  /**
   * Returns the configured value for the type of the truststore specified by {@link #getHttpClientTruststorePath()}.
   *
   * @return a truststore type
   */
  String getHttpClientTruststoreType();

  /**
   * Returns the configured value for the alias name to use when to looking up the HTTP client's
   * truststore password.
   *
   * @return an alias name
   */
  String getHttpClientTruststorePasswordAlias();

  int getThreadPoolMax();

  int getHttpServerRequestBuffer();

  int getHttpServerRequestHeaderBuffer();

  int getHttpServerResponseBuffer();

  int getHttpServerResponseHeaderBuffer();

  int getGatewayDeploymentsBackupVersionLimit();

  long getGatewayDeploymentsBackupAgeLimit();

  long getGatewayIdleTimeout();

  /**
   * Returns the configured value for the path to the keystore holding the key and certificate for the
   * Gateway's TLS identity.
   *
   * @return a path to the keystore file; or <code>null</code> if not set
   */
  String getIdentityKeystorePath();

  /**
   * Returns the configured value for the type of the keystore holding the Gateway's identity.
   *
   * @return a keystore type
   */
  String getIdentityKeystoreType();

  /**
   * Returns the configured value for the alias name to use when to looking up the Gateway's identity
   * keystore's password.
   *
   * @return an alias name
   */
  String getIdentityKeystorePasswordAlias();

  /**
   * Returns the configured value for the alias name to use when to looking up the Gateway's identity
   * from the Gateway's identity keystore.
   *
   * @return an alias name
   */
  String getIdentityKeyAlias();

  /**
   * Returns the configured value for the alias name to use when to looking up the Gateway's identity
   * key's password.
   *
   * @return an alias name
   */
  String getIdentityKeyPassphraseAlias();

  String getSigningKeystoreName();

  /**
   * Returns the calculated value for the path to the keystore holding the key and certificate for the
   * Gateway's signing key.
   *
   * @return a path to the keystore file; or <code>null</code> if not set
   */
  String getSigningKeystorePath();

  /**
   * Returns the configured value for the type of the keystore holding the Gateway's signing key.
   *
   * @return a keystore type
   */
  String getSigningKeystoreType();

  String getSigningKeyAlias();

  /**
   * Returns the configured value for the alias name to use when to looking up the Gateway's signing
   * keystore's password.
   *
   * @return an alias name
   */
  String getSigningKeystorePasswordAlias();

  /**
   * Returns the configured value for the alias name to use when to looking up the signing key's
   * password.
   *
   * @return an alias name
   */
  String getSigningKeyPassphraseAlias();


  List<String> getGlobalRulesServices();

  /**
   * Returns true if websocket feature enabled else false.
   * Default is false.
   * @since 0.10
   * @return true if websocket feature is enabled
   */
  boolean isWebsocketEnabled();

  /**
   * Websocket connection max text message size.
   * @since 0.10
   * @return max text message size
   */
  int getWebsocketMaxTextMessageSize();

  /**
   * Websocket connection max binary message size.
   * @since 0.10
   * @return max binary message size
   */
  int getWebsocketMaxBinaryMessageSize();

  /**
   * Websocket connection max text message buffer size.
   * @since 0.10
   * @return buffer size
   */
  int getWebsocketMaxTextMessageBufferSize();

  /**
   * Websocket connection max binary message buffer size.
   * @since 0.10
   * @return buffer size
   */
  int getWebsocketMaxBinaryMessageBufferSize();

  /**
   * Websocket connection input buffer size.
   * @since 0.10
   * @return buffer size
   */
  int getWebsocketInputBufferSize();

  /**
   * Websocket connection async write timeout.
   * @since 0.10
   * @return timeout
   */
  int getWebsocketAsyncWriteTimeout();

  /**
   * Websocket connection idle timeout.
   * @since 0.10
   * @return timeout
   */
  int getWebsocketIdleTimeout();

  boolean isMetricsEnabled();

  boolean isJmxMetricsReportingEnabled();

  boolean isGraphiteMetricsReportingEnabled();

  String getGraphiteHost();

  int getGraphitePort();

  int getGraphiteReportingFrequency();

  /**
   * Enable cookie scoping to gateway path
   *
   * @return true if cookie scoping to path is enabled
   * @since 0.13
   */
  boolean isCookieScopingToPathEnabled();

  /**
   * Configured name of the HTTP Header that is expected
   * to be set by a proxy in front of the gateway.
   * @return header name
   */
  String getHeaderNameForRemoteAddress();

  /**
   * Configured Algorithm name to be used by the CryptoService
   * and MasterService implementations
   * @return algorithm
   */
  String getAlgorithm();

  /**
   * Configured Algorithm name to be used by the CryptoService
   * for password based encryption
   * @return algorithm
   */
  String getPBEAlgorithm();

  /**
   * Configured Transformation name to be used by the CryptoService
   * and MasterService implementations
   * @return transformation name
   */
  String getTransformation();

  /**
   * Configured SaltSize to be used by the CryptoService
   * and MasterService implementations
   * @return salt size
   */
  String getSaltSize();

  /**
   * Configured IterationCount to be used by the CryptoService
   * and MasterService implementations
   * @return iteration count
   */
  String getIterationCount();

  /**
   * Configured KeyLength to be used by the CryptoService
   * and MasterService implementations
   * @return key length
   */
  String getKeyLength();

  /**
   * Map of Topology names and their ports.
   * @return Map of Topology names and their ports.
   */
  Map<String, Integer> getGatewayPortMappings();

  /**
   * Is the Port Mapping feature on
   * @return true if port mapping enabled
   */
  boolean isGatewayPortMappingEnabled();

  /**
   * Is the Server header suppressed
   * @return turn if server header enabled
   */
  boolean isGatewayServerHeaderEnabled();

  /**
   * Determine the default address for discovering service endpoint details.
   *
   * @return A valid discovery source address, or null (because this property is optional).
   */
  String getDefaultDiscoveryAddress();

  /**
   * Determine the default target cluster for discovering service endpoint details.
   *
   * @return A valid cluster name, or null (because this property is optional).
   */
  String getDefaultDiscoveryCluster();

  /**
   *
   * @param type The type of cluster configuration monitor for which the interval should be returned.
   *
   * @return The polling interval configuration value, or -1 if it has not been configured.
   */
  int getClusterMonitorPollingInterval(String type);

  /**
   *
   * @param type The type of cluster configuration monitor for which the interval should be returned.
   *
   * @return The enabled status of the specified type of cluster configuration monitor.
   */
  boolean isClusterMonitorEnabled(String type);

  /**
   * @return The list of the names of any remote registry configurations defined herein.
   */
  List<String> getRemoteRegistryConfigurationNames();

  /**
   *
   * @param name The name of the remote registry configuration
   *
   * @return The configuration associated with the specified name.
   */
  String getRemoteRegistryConfiguration(String name);

  /**
   *
   * @return The name of a remote configuration registry client
   */
  String getRemoteConfigurationMonitorClientName();

  /**
   * When new remote registry entries must be created, or new ACLs applied to existing entries, this method indicates
   * whether unauthenticated connections should be given read access to those entries.
   *
   * @return true, if unauthenticated clients should be allowed to access remote registry entries.
   */
  boolean allowUnauthenticatedRemoteRegistryReadAccess();

  /**
   * Returns whether the Remote Alias Service is enabled or not.
   *
   * This value also depends on whether the remote configuration registry is enabled or not.
   * If it is enabled, then this option takes effect, else this option has no effect.
   *
   * @return true, if the remote alias service is enabled; otherwise, false;
   */
  boolean isRemoteAliasServiceEnabled();

  /**
   * Returns prefix for the remote alias service configuration
   *
   * @return the prefix for the remote alias service configuration
   */
  String getRemoteAliasServiceConfigurationPrefix();

  /**
   * Uses result of getRemoteAliasServiceConfigurationPrefix to return configurations
   *
   * @return Map of configurations that apply to the remote alias service
   */
  Map<String, String> getRemoteAliasServiceConfiguration();

  /**
   * Get the list of those topology names which should be treated as read-only, regardless of their actual read-write
   * status.
   *
   * @return A list of the names of those topologies which should be treated as read-only.
   */
  List<String> getReadOnlyOverrideTopologyNames();

  /**
   * Get the comma separated list of group names that represent Knox Admin users
   * @return comma separate list of admin group names
   */
  String getKnoxAdminGroups();

  /**
   * Get the comma separated list of user names that represent Knox Admin users
   * @return comma separated list of admin user names
   */
  String getKnoxAdminUsers();

  /**
   * Custom header name to be used to pass the authenticated principal
   * via dispatch
   * @since 1.1.0
   * @return federation header
   */
  String getFederationHeaderName();

  /**
   * Get the list of topology names that should be redeployed on restart.
   * manager and admin are default topologies as they may depend on gateway-site.xml
   * configuration for deployment time config.
   * @return list of topology names
   */
  List<String> getAutoDeployTopologyNames();

  /*
   * Get the semicolon-delimited set of regular expressions defining to which hosts Knox will permit requests to be
   * dispatched.
   *
   * @return The whitelist, which will be null if none is configured (in which case, requests to any host are permitted).
   */
  String getDispatchWhitelist();

  /**
   * Get the set of service roles to which the dispatch whitelist will be applied.
   *
   * @return The service roles, or an empty list if none are configured.
   */
  List<String> getDispatchWhitelistServices();

  /**
   * Returns true when strict topology validation is enabled,
   * in which case if topology validation fails Knox will throw
   * a runtime exception. If false and topology validation fails
   * Knox will log an ERROR and move on.
   *
   * @since 1.1.0
   * @return true if topology validation enabled
   */
  boolean isTopologyValidationEnabled();

  /**
   * Returns a list of services that need service name appended to
   * X-Forward-Context header as a result of which the new header would look
   * /{gateway}/{sandbox}/{serviceName}
   *
   * @return List of service names for which service name needs to be appended
   * to X-Forward-Context header, can be empty list.
   * @since 1.3.0
   */
  List<String> getXForwardContextAppendServices();

  /**
   * Returns a set of service principal names that indicate which services to ignore doAs requests.
   * <p>
   * If a service in the returned set sends a Kerberos-authenticated request to the Gateway, the doAs
   * query parameter is to be ignored; thus leaving the authenticated user details intact.
   * <p>
   * If the (authenticated) service is not authorized to set the specified proxy user (see information
   * related to hadoop.proxyuser.... properties) an error will not be returned since the request to
   * impersonate users is to be ignored.
   *
   * @return a set of service principal names that indicate which services to ignore doAs request
   */
  Set<String> getServicesToIgnoreDoAs();

  /*
   * Returns refresh interval in ms
   *
   * @return refresh interval in ms
   * @since 1.3.0
   */
  int getConfigRefreshInterval();

  /**
   * Get the value of the <code>name</code> property, <code>null</code> if
   * no such property exists.
   *
   * @param name the property name
   * @return the value of the <code>name</code> or null if no such property exists.
   */
  String get(String name);

  /**
   * @return the monitoring interval (in milliseconds) of Cloudera Manager descriptors
   */
  long getClouderaManagerDescriptorsMonitoringInterval();

  /**
   * @return the monitoring interval (in milliseconds) of Cloudera Manager advanced service discovery configuration
   */
  long getClouderaManagerAdvancedServiceDiscoveryConfigurationMonitoringInterval();

  /**
   * @return true, if state for tokens issued by the Knox Token service should be managed by Knox.
   */
  boolean isServerManagedTokenStateEnabled();


  /**
   * Return the configured interval (in seconds) at which token eviction job should run
   * @return eviction job run interval in seconds
   */
  long getKnoxTokenEvictionInterval();

  /**
   * Return the configured grace period (in seconds) after which an expired token should be evicted
   * @return eviction grace period in seconds
   */
  long getKnoxTokenEvictionGracePeriod();

  /**
   * @return returns whether know token permissive validation is enabled
   */
  boolean isKnoxTokenPermissiveValidationEnabled();
}
