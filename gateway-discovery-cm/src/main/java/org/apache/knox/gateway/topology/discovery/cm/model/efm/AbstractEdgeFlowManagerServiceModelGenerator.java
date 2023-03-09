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

package org.apache.knox.gateway.topology.discovery.cm.model.efm;

import static java.lang.Boolean.parseBoolean;
import static java.lang.String.format;

import com.cloudera.api.swagger.client.ApiException;
import com.cloudera.api.swagger.model.ApiConfigList;
import com.cloudera.api.swagger.model.ApiRole;
import com.cloudera.api.swagger.model.ApiService;
import com.cloudera.api.swagger.model.ApiServiceConfig;
import java.util.Locale;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModel;
import org.apache.knox.gateway.topology.discovery.cm.model.AbstractServiceModelGenerator;

public abstract class AbstractEdgeFlowManagerServiceModelGenerator extends AbstractServiceModelGenerator {

    static final String SSL_ENABLED = "ssl_enabled";

    static final String SERVICE_TYPE = "EFM";
    static final String ROLE_TYPE = "EFM_SERVER";

    private static final String HTTPS = "https";
    private static final String HTTP = "http";
    private static final String URL_TEMPLATE = "%s://%s:%s";

    @Override
    public String getServiceType() {
        return SERVICE_TYPE;
    }

    @Override
    public String getRoleType() {
        return ROLE_TYPE;
    }

    @Override
    public ServiceModel generateService(ApiService service, ApiServiceConfig serviceConfig,
        ApiRole role, ApiConfigList roleConfig) throws ApiException {
        String hostname = role.getHostRef().getHostname();
        String sslEnabled = getRoleConfigValue(roleConfig, SSL_ENABLED);
        String scheme = parseBoolean(sslEnabled) ? HTTPS : HTTP;
        String port = getRoleConfigValue(roleConfig, getPortPropertyName());

        ServiceModel serviceModel = new ServiceModel(
            getModelType(), getService(), getServiceType(), getRoleType(),
            format(Locale.getDefault(), URL_TEMPLATE, scheme, hostname, port));
        serviceModel.addRoleProperty(getRoleType(), SSL_ENABLED, sslEnabled);
        serviceModel.addRoleProperty(getRoleType(), getPortPropertyName(), port);
        return serviceModel;
    }

    protected abstract String getPortPropertyName();
}