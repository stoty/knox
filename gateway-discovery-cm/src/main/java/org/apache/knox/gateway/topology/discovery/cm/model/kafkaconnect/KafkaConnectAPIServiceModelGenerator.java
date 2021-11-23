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
package org.apache.knox.gateway.topology.discovery.cm.model.kafkaconnect;

import com.cloudera.api.swagger.client.ApiException;
import com.cloudera.api.swagger.model.ApiConfigList;
import com.cloudera.api.swagger.model.ApiRole;
import com.cloudera.api.swagger.model.ApiService;
import com.cloudera.api.swagger.model.ApiServiceConfig;

import java.util.Locale;

import org.apache.knox.gateway.topology.discovery.cm.ServiceModel;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModel.Type;
import org.apache.knox.gateway.topology.discovery.cm.model.AbstractServiceModelGenerator;

public class KafkaConnectAPIServiceModelGenerator extends AbstractServiceModelGenerator {

    public static final String KNOX_SERVICE = "KAFKA_CONNECT";
    public static final String CM_SERVICE_TYPE = "KAFKA";
    public static final String ROLE_TYPE = "KAFKA_CONNECT";

    public static final String SSL_ENABLED = "ssl_enabled";
    public static final String HTTP_PORT = "rest.port";
    public static final String HTTPS_PORT = "secure.rest.port";

    @Override
    public String getService() {
        return KNOX_SERVICE;
    }

    @Override
    public String getServiceType() {
        return CM_SERVICE_TYPE;
    }

    @Override
    public String getRoleType() {
        return ROLE_TYPE;
    }

    @Override
    public Type getModelType() {
        return Type.API;
    }

    @Override
    public ServiceModel generateService(ApiService service, ApiServiceConfig serviceConfig, ApiRole role, ApiConfigList roleConfig) throws ApiException {
        boolean sslEnabled = Boolean.parseBoolean(getRoleConfigValue(roleConfig, SSL_ENABLED));

        String portKey = HTTP_PORT;
        String scheme = "http";
        String hostname = role.getHostRef().getHostname();
        String port = getRoleConfigValue(roleConfig, HTTP_PORT);

        if (sslEnabled) {
            portKey = HTTPS_PORT;
            scheme = "https";
            port = getRoleConfigValue(roleConfig, HTTPS_PORT);
        }

        ServiceModel model = createServiceModel(String.format(Locale.getDefault(), "%s://%s:%s/", scheme, hostname, port));
        model.addRoleProperty(ROLE_TYPE, SSL_ENABLED, Boolean.toString(sslEnabled));
        model.addRoleProperty(ROLE_TYPE, portKey, port);

        return model;
    }

}
