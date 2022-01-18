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
package org.apache.knox.gateway.topology.discovery.cm;

import com.cloudera.api.swagger.RolesResourceApi;
import com.cloudera.api.swagger.ServicesResourceApi;
import com.cloudera.api.swagger.client.ApiException;
import com.cloudera.api.swagger.model.ApiConfigList;
import com.cloudera.api.swagger.model.ApiRole;
import com.cloudera.api.swagger.model.ApiRoleList;
import com.cloudera.api.swagger.model.ApiService;
import com.cloudera.api.swagger.model.ApiServiceConfig;
import com.cloudera.api.swagger.model.ApiServiceList;
import org.apache.knox.gateway.GatewayServer;
import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.services.GatewayServices;
import org.apache.knox.gateway.services.ServiceType;
import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.KeystoreService;
import org.apache.knox.gateway.topology.ClusterConfigurationMonitorService;
import org.apache.knox.gateway.topology.discovery.ClusterConfigurationMonitor;
import org.apache.knox.gateway.topology.discovery.ServiceDiscovery;
import org.apache.knox.gateway.topology.discovery.ServiceDiscoveryConfig;
import org.apache.knox.gateway.topology.discovery.cm.monitor.ClouderaManagerClusterConfigurationMonitor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;


/**
 * ClouderaManager-based service discovery implementation.
 */
public class ClouderaManagerServiceDiscovery implements ServiceDiscovery, ClusterConfigurationMonitor.ConfigurationChangeListener {

  static final String TYPE = "ClouderaManager";

  private static final ClouderaManagerServiceDiscoveryMessages log =
                                        MessagesFactory.get(ClouderaManagerServiceDiscoveryMessages.class);

  static final String API_PATH = "api/v32";

  private static final String VIEW_SUMMARY     = "summary";
  private static final String VIEW_FULL        = "full";

  static final String DEFAULT_USER_ALIAS = "cm.discovery.user";
  static final String DEFAULT_PWD_ALIAS  = "cm.discovery.password";

  public static final String CM_SERVICE_TYPE  = "CM";
  public static final String CM_ROLE_TYPE  = "CM_SERVER";

  private static Map<String, List<ServiceModelGenerator>> serviceModelGenerators = new HashMap<>();
  static {
    ServiceLoader<ServiceModelGenerator> loader = ServiceLoader.load(ServiceModelGenerator.class);
    for (ServiceModelGenerator serviceModelGenerator : loader) {
      List<ServiceModelGenerator> smgList =
          serviceModelGenerators.computeIfAbsent(serviceModelGenerator.getServiceType(), k -> new ArrayList<>());
      smgList.add(serviceModelGenerator);
    }
  }

  private boolean debug;

  private AliasService aliasService;
  private KeystoreService keystoreService;

  private ClouderaManagerClusterConfigurationMonitor configChangeMonitor;

  private final ClouderaManagerServiceDiscoveryRepository repository = ClouderaManagerServiceDiscoveryRepository.getInstance();

  ClouderaManagerServiceDiscovery(GatewayConfig gatewayConfig) {
    this(false, gatewayConfig);
  }

  ClouderaManagerServiceDiscovery(boolean debug, GatewayConfig gatewayConfig) {
    GatewayServices gwServices = GatewayServer.getGatewayServices();
    if (gwServices != null) {
      this.aliasService = gwServices.getService(ServiceType.ALIAS_SERVICE);
      this.keystoreService = gwServices.getService(ServiceType.KEYSTORE_SERVICE);
    }
    this.debug = debug;
    this.configChangeMonitor = getConfigurationChangeMonitor();

    if (gatewayConfig != null) {
      repository.setCacheEntryTTL(gatewayConfig.getClouderaManagerServiceDiscoveryRepositoryEntryTTL());
    }
  }

  @Override
  public String getType() {
    return TYPE;
  }

  private DiscoveryApiClient getClient(ServiceDiscoveryConfig discoveryConfig) {
    String discoveryAddress = discoveryConfig.getAddress();
    if (discoveryAddress == null || discoveryAddress.isEmpty()) {
      log.missingDiscoveryAddress();
      throw new IllegalArgumentException("Missing or invalid discovery address.");
    }

    DiscoveryApiClient client = new DiscoveryApiClient(discoveryConfig, aliasService, keystoreService);
    client.setDebugging(debug);
    return client;
  }

  /**
   * Get the ClouderaManager configuration change monitor from the associated gateway service.
   */
  private ClouderaManagerClusterConfigurationMonitor getConfigurationChangeMonitor() {
    ClouderaManagerClusterConfigurationMonitor cmMonitor = null;

    try {
      GatewayServices gwServices = GatewayServer.getGatewayServices();
      if (gwServices != null) {
        ClusterConfigurationMonitorService clusterMonitorService =
            GatewayServer.getGatewayServices().getService(ServiceType.CLUSTER_CONFIGURATION_MONITOR_SERVICE);
        ClusterConfigurationMonitor monitor =
            clusterMonitorService.getMonitor(ClouderaManagerClusterConfigurationMonitor.getType());
        if (monitor != null && ClouderaManagerClusterConfigurationMonitor.class.isAssignableFrom(monitor.getClass())) {
          cmMonitor = (ClouderaManagerClusterConfigurationMonitor) monitor;
          cmMonitor.addListener(this);
        }
      }
    } catch (Exception e) {
      log.errorAccessingConfigurationChangeMonitor(e);
    }
    return cmMonitor;
  }

  @Override
  public ClouderaManagerCluster discover(GatewayConfig          gatewayConfig,
                                         ServiceDiscoveryConfig discoveryConfig,
                                         String                 clusterName) {
    return discover(gatewayConfig, discoveryConfig, clusterName, Collections.emptySet());
  }

  @Override
  public ClouderaManagerCluster discover(GatewayConfig          gatewayConfig,
                                         ServiceDiscoveryConfig discoveryConfig,
                                         String                 clusterName,
                                         Collection<String>     includedServices) {
    return discover(discoveryConfig, clusterName, includedServices, getClient(discoveryConfig));
  }

  protected ClouderaManagerCluster discover(ServiceDiscoveryConfig discoveryConfig,
                                            String clusterName,
                                            Collection<String> includedServices,
                                            DiscoveryApiClient client) {
    ClouderaManagerCluster cluster = null;

    if (clusterName == null || clusterName.isEmpty()) {
      log.missingDiscoveryCluster();
      throw new IllegalArgumentException("The cluster configuration is missing from, or invalid in, the discovery configuration.");
    }

    try {
      cluster = discoverCluster(client, clusterName, includedServices);

      if (configChangeMonitor != null && cluster != null) {
        // Notify the cluster config monitor about these cluster configuration details
        configChangeMonitor.addServiceConfiguration(cluster, discoveryConfig);
      }
    } catch (ApiException e) {
      log.clusterDiscoveryError(clusterName, e);
    }

    return cluster;
  }

  private ClouderaManagerCluster discoverCluster(DiscoveryApiClient client, String clusterName, Collection<String> includedServices)
      throws ApiException {
    ServicesResourceApi servicesResourceApi = new ServicesResourceApi(client);
    RolesResourceApi rolesResourceApi = new RolesResourceApi(client);

    log.discoveringCluster(clusterName);

    repository.registerCluster(client.getConfig());

    Set<ServiceModel> serviceModels = new HashSet<>();

    List<ApiService> serviceList = getClusterServices(client.getConfig(), servicesResourceApi);
    if (serviceList != null) {
      /*
      Since Cloudera Manager does not have a service for itself, we will add a skeleton CM
      service so that we can add CM service to topology when auto-discovery is
      turned on and CM service is selected in the descriptor
      */
      final ApiService cmService = new ApiService();
      cmService.setName(CM_SERVICE_TYPE.toLowerCase(Locale.ROOT));
      cmService.setType(CM_SERVICE_TYPE);
      serviceList.add(cmService);

      for (ApiService service : serviceList) {
        final List<ServiceModelGenerator> modelGenerators = serviceModelGenerators.get(service.getType());
        if (shouldSkipServiceDiscovery(modelGenerators, includedServices)) {
          log.skipServiceDiscovery(service.getName(), service.getType());
          continue;
        }
        log.discoveringService(service.getName(), service.getType());
        ApiServiceConfig serviceConfig = null;
        /* no reason to check service config for CM service */
        if(!CM_SERVICE_TYPE.equals(service.getType())) {
          serviceConfig = getServiceConfig(client.getConfig(), servicesResourceApi, service);
        }
        ApiRoleList roleList = getRoles(client.getConfig(), rolesResourceApi, clusterName, service);
        if (roleList != null) {
          for (ApiRole role : roleList.getItems()) {
            String roleName = role.getName();
            log.discoveringServiceRole(roleName, role.getType());

            ApiConfigList roleConfig = null;
            /* no reason to check role config for CM service */
            if (!CM_SERVICE_TYPE.equals(service.getType())) {
              roleConfig = getRoleConfig(client.getConfig(), rolesResourceApi, service, role);
            }

            if (modelGenerators != null) {
              for (ServiceModelGenerator serviceModelGenerator : modelGenerators) {
                ServiceModelGeneratorHandleResponse response = serviceModelGenerator.handles(service, serviceConfig, role, roleConfig);
                if (response.handled()) {
                  serviceModelGenerator.setApiClient(client);
                  ServiceModel serviceModel = serviceModelGenerator.generateService(service, serviceConfig, role, roleConfig);
                  serviceModels.add(serviceModel);
                } else if (!response.getConfigurationIssues().isEmpty()) {
                  log.serviceRoleHasConfigurationIssues(roleName, String.join(";", response.getConfigurationIssues()));
                }
              }
            }

            log.discoveredServiceRole(roleName, role.getType());
          }
        }

        log.discoveredService(service.getName(), service.getType());
      }

      ClouderaManagerCluster cluster = new ClouderaManagerCluster(clusterName);
      cluster.addServiceModels(serviceModels);
      return cluster;
    }

    return null;
  }

  private boolean shouldSkipServiceDiscovery(List<ServiceModelGenerator> modelGenerators, Collection<String> includedServices) {
    if (includedServices == null || includedServices.isEmpty()) {
      // per the contract of org.apache.knox.gateway.topology.discovery.ServiceDiscovery.discover(GatewayConfig, ServiceDiscoveryConfig, String, Collection<String>):
      // if included services is null or empty -> discover all services in the given cluster
      return false;
    }

    if (modelGenerators != null) {
      for (ServiceModelGenerator modelGenerator : modelGenerators) {
        if (includedServices.contains(modelGenerator.getService())) {
          return false;
        }
      }
    }
    return true;
  }

  private List<ApiService> getClusterServices(ServiceDiscoveryConfig serviceDiscoveryConfig, ServicesResourceApi servicesResourceApi) {
    log.lookupClusterServicesFromRepository();
    List<ApiService> services = repository.getServices(serviceDiscoveryConfig);
    if (services == null || services.isEmpty()) {
      try {
        log.lookupClusterServicesFromCM();
        final ApiServiceList serviceList = servicesResourceApi.readServices(serviceDiscoveryConfig.getCluster(), VIEW_SUMMARY);
        services = serviceList == null ? new ArrayList<ApiService>() : serviceList.getItems();

        // make sure that services are populated in the repository
        services.forEach(service -> repository.addService(serviceDiscoveryConfig, service));
      } catch (ApiException e) {
        log.failedToAccessServiceConfigs(serviceDiscoveryConfig.getCluster(), e);
      }
    }
    return services;
  }

  private ApiServiceConfig getServiceConfig(ServiceDiscoveryConfig serviceDiscoveryConfig, ServicesResourceApi servicesResourceApi, ApiService service) {
    log.lookupServiceConfigsFromRepository();
    // first, try in the service discovery repository
    ApiServiceConfig serviceConfig = repository.getServiceConfig(serviceDiscoveryConfig, service);

    if (serviceConfig == null) {
      // no service config in the repository -> query CM
      try {
        log.lookupServiceConfigsFromCM();
        serviceConfig = servicesResourceApi.readServiceConfig(serviceDiscoveryConfig.getCluster(), service.getName(), VIEW_FULL);

        // make sure that service config is populated in the service discovery repository to avoid subsequent CM calls
        repository.addServiceConfig(serviceDiscoveryConfig, service, serviceConfig);
      } catch (Exception e) {
        log.failedToAccessServiceConfigs(serviceDiscoveryConfig.getCluster(), e);
      }
    }
    return serviceConfig;
  }

  private ApiRoleList getRoles(ServiceDiscoveryConfig serviceDiscoveryConfig, RolesResourceApi rolesResourceApi, String clusterName, ApiService service) {
    log.lookupRolesFromRepository();
    //first, try in the service discovery repository
    ApiRoleList roles  = repository.getRoles(serviceDiscoveryConfig, service);
    if (roles == null || roles.getItems() == null) {
      // no roles in the repository -> query CM
      final String serviceName = service.getName();
      try {
        log.lookupRolesFromCM();
        /* Populate roles for CM Service since they are not discoverable */
        if(CM_SERVICE_TYPE.equalsIgnoreCase(serviceName)) {
          roles = new ApiRoleList();
          final ApiRole cmRole = new ApiRole();
          cmRole.setName(CM_ROLE_TYPE);
          cmRole.setType(CM_ROLE_TYPE);
          roles.addItemsItem(cmRole);
        } else {
          roles = rolesResourceApi.readRoles(clusterName, serviceName, "", VIEW_SUMMARY);
        }

        // make sure that role is populated in the service discovery repository to avoid subsequent CM calls
        repository.addRoles(serviceDiscoveryConfig, service, roles);
      } catch (Exception e) {
        log.failedToAccessServiceRoleConfigs(serviceName, "N/A", clusterName, e);
      }
    }

    return roles;
  }

  private ApiConfigList getRoleConfig(ServiceDiscoveryConfig serviceDiscoveryConfig, RolesResourceApi rolesResourceApi, ApiService service, ApiRole role) {
    log.lookupRoleConfigsFromRepository();
    // first, try in the service discovery repository
    ApiConfigList configList = repository.getRoleConfigs(serviceDiscoveryConfig, service, role);
    if (configList == null || configList.getItems() == null) {
      // no role configs in the repository -> query CM
      try {
        log.lookupRoleConfigsFromCM();
        configList = rolesResourceApi.readRoleConfig(serviceDiscoveryConfig.getCluster(), role.getName(), service.getName(), VIEW_FULL);

        // make sure that role config is populated in the service discovery repository to avoid subsequent CM calls
        repository.addRoleConfigs(serviceDiscoveryConfig, service, role, configList);
      } catch (Exception e) {
        log.failedToAccessServiceRoleConfigs(service.getName(), role.getName(), serviceDiscoveryConfig.getCluster(), e);
      }
    }
    return configList;
  }

  @Override
  public void onConfigurationChange(String source, String clusterName) {
    log.clearServiceDiscoveryRepository();
    repository.clear();
  }

}
