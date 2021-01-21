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
package org.apache.knox.gateway.topology.discovery.cm.model.hdfs;

import com.cloudera.api.swagger.client.ApiException;
import com.cloudera.api.swagger.model.ApiConfigList;
import com.cloudera.api.swagger.model.ApiRole;
import com.cloudera.api.swagger.model.ApiService;
import com.cloudera.api.swagger.model.ApiServiceConfig;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModel;

import java.util.Locale;
import java.util.Map;

public class HdfsUIServiceModelGenerator extends NameNodeServiceModelGenerator {
  public static final String SERVICE = "HDFSUI";

  static final String SSL_ENABLED = "hdfs_hadoop_ssl_enabled";
  static final String HTTP_PORT   = "dfs_http_port";
  static final String HTTPS_PORT  = "dfs_https_port";

  @Override
  public String getService() {
    return SERVICE;
  }

  @Override
  public ServiceModel.Type getModelType() {
    return ServiceModel.Type.UI;
  }

  @Override
  public ServiceModel generateService(ApiService       service,
                                      ApiServiceConfig serviceConfig,
                                      ApiRole          role,
                                      ApiConfigList    roleConfig) throws ApiException {
    String hostname = role.getHostRef().getHostname();
    String scheme;
    String port;
    boolean sslEnabled = Boolean.parseBoolean(getServiceConfigValue(serviceConfig, SSL_ENABLED));
    if(sslEnabled) {
      scheme = "https";
      port = getRoleConfigValue(roleConfig, HTTPS_PORT);
    } else {
      scheme = "http";
      port = getRoleConfigValue(roleConfig, HTTP_PORT);
    }
    String namenodeUrl = String.format(Locale.getDefault(), "%s://%s:%s", scheme, hostname, port);

    ServiceModel model = createServiceModel(namenodeUrl);
    model.addServiceProperty(SSL_ENABLED, getServiceConfigValue(serviceConfig, SSL_ENABLED));
    model.addRoleProperty(role.getType(), HTTPS_PORT, getRoleConfigValue(roleConfig, HTTPS_PORT));
    model.addRoleProperty(role.getType(), HTTP_PORT, getRoleConfigValue(roleConfig, HTTP_PORT));

    ServiceModel parent = super.generateService(service, serviceConfig, role, roleConfig);
    addParentModelMetadata(model, parent);

    return model;
  }

  protected void addParentModelMetadata(final ServiceModel model, final ServiceModel parent) {
    // Add parent model properties
    for (Map.Entry<String, String> parentProp : parent.getQualifyingServiceParams().entrySet()) {
      model.addQualifyingServiceParam(parentProp.getKey(), parentProp.getValue());
    }

    // Add parent service properties
    for (Map.Entry<String, String> parentProp : parent.getServiceProperties().entrySet()) {
      model.addServiceProperty(parentProp.getKey(), parentProp.getValue());
    }

    // Add parent role properties
    for (Map.Entry<String, Map<String, String>> parentProps : parent.getRoleProperties().entrySet()) {
      for (Map.Entry<String, String> prop : parentProps.getValue().entrySet()) {
        model.addRoleProperty(parentProps.getKey(), prop.getKey(), prop.getValue());
      }
    }
  }

}
