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

import java.util.Properties;

import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.CryptoService;

/**
 *
 */
public interface KnoxCloudCredentialsClient {

  String ROLE_TYPE_USER     = "USER_ROLE";
  String ROLE_TYPE_GROUP    = "GROUP_ROLE";
  String ROLE_TYPE_EXPLICIT = "EXPLICIT_ROLE";

  /**
   * Initialize client with the context from the topology
   * params that are relevant to the cloud-specific client.
   *
   * @param context
   */
  void init(Properties context);


  CloudClientConfigurationProvider getConfigProvider();


  void setConfigProvider(CloudClientConfigurationProvider configProvider);


  /**
   * Set the AliasService implementation currently configured for the
   * gateway, in order to locate the idbroker credentials for the given
   * topology instance. Topology name is in the Properties provided to
   * the init method.
   *
   * @param aliasService The AliasService
   */
  void setAliasService(AliasService aliasService);

  /**
   * Set CryptoService used by the gateway to encrypt credentials that
   * are stored in cache.
   * @param cryptoService cryptoService
   */
  void setCryptoService(CryptoService cryptoService);

  /**
   * Name of the specific provider implementation to be resolved
   * by the KnoxCloudCredentialsClientManager via ServiceLoader and the name
   * configured within the topology.
   */
  String getName();


  /**
   * Get an opaque Object representation of the cloud-specific credentials.
   * This method will only be called by callers that are aware
   * of the actual form of the credentials in the given context
   * and therefore able to cast it appropriately.
   *
   * @return opaque object
   */
  Object getCredentials();


  /**
   * Get an opaque Object representation of the cloud-specific credentials.
   * This method will only be called by callers that are aware
   * of the actual form of the credentials in the given context
   * and therefore able to cast it appropriately.
   *
   * @return opaque object
   */
  Object getCredentialsForRole(String role);


  /**
   * Get an opaque Object representation of the cloud-specific credentials.
   * This method will only be called by callers that are aware
   * of the actual form of the credentials in the given context
   * and therefore able to cast it appropriately.
   *
   * @return opaque object
   */
  Object getCredentialsForRole(String roleType, String id);


}
