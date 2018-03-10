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

import java.security.AccessController;
import java.security.Principal;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.security.GroupPrincipal;
import org.apache.knox.gateway.security.SubjectUtils;
import org.apache.knox.gateway.services.security.AliasService;

import javax.security.auth.Subject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

public abstract class AbstractKnoxCloudCredentialsClient implements KnoxCloudCredentialsClient {


  protected final static String ROLE_TYPE_USER     = "USER_ROLE";
  protected final static String ROLE_TYPE_GROUP    = "GROUP_ROLE";
  protected final static String ROLE_TYPE_EXPLICIT = "EXPLICIT_ROLE";

  private static IdBrokerServiceMessages log = MessagesFactory.get(IdBrokerServiceMessages.class);

  private CloudClientConfigurationProvider cloudConfigProvider = null;
  protected AliasService aliasService;
  protected String topologyName;

  public AbstractKnoxCloudCredentialsClient() {
    super();
  }

  @Override
  public void init(Properties context) {
    topologyName = context.getProperty("topology.name");
  }


  public CloudClientConfigurationProvider getConfigProvider() {
    return cloudConfigProvider;
  }

  public void setConfigProvider(CloudClientConfigurationProvider configProvider) {
    this.cloudConfigProvider = configProvider;
  }

  @Override
  public void setAliasService(AliasService aliasService) {
    this.aliasService = aliasService;
  }

  @Override
  public Object getCredentialsForRole(String roleType, String id) {
    return getCredentialsForRole(getRole(roleType, id));
  }

  protected String getRole() {
    return getRole("", null);
  }

  protected String getRole(String roleType, String id) {
    String role = null;

    switch (roleType) {
      case ROLE_TYPE_USER:
        role = getUserRole();
        break;
      case ROLE_TYPE_GROUP:
        role = getGroupRole(id);
        break;
      case ROLE_TYPE_EXPLICIT:
        if (id != null && (id.equals(getUserRole()) || id.equals(getGroupRole(null)))) {
          role = id;
        }
        break;
      default:
        role = getUserRole();
        if (role == null) {
          role = getGroupRole(null);
        }
    }

    if (role == null) {
      throw new WebApplicationException("No suitable role is defined.", Response.Status.FORBIDDEN);
    }

    return role;
  }

  protected String getUserRole() {
    String role = null;

    // Try to identify a role for the authenticated user
    Subject subject = Subject.getSubject(AccessController.getContext());
    if (subject != null) {
      String username = getEffectiveUserName(subject);
      role = getConfigProvider().getConfig().getUserRole(username);
      if (role == null) {
        log.noRoleForUser(username);
      }
    }

    return role;
  }

  protected String getGroupRole(String id) {
    String role = null;

    Subject subject = Subject.getSubject(AccessController.getContext());
    if (subject != null) {
      Set<String> groups = getGroupNames(subject);

      // If an explicit group is specified, and the authenticated user belongs to that group, get the mapped role
      if (id != null) {
        if (groups.contains(id)) {
          role = getConfigProvider().getConfig().getGroupRole(id);
          if (role == null) {
            log.noRoleForGroup(id);
          }
        } else {
          log.userNotInGroup(id);
        }
      } else {
        // Otherwise, use the first group for which there is a mapped role
        for (String group : groups) {
          role = getConfigProvider().getConfig().getGroupRole(group);
          if (role != null) {
            break;
          }
        }
        if (role == null) {
          log.noRoleForGroups(getEffectiveUserName(subject));
        }
      }
    }

    return role;
  }

  protected Set<String> getGroupNames(Subject subject) {
    Set<String> groupNames = new HashSet<>();
    Object[] groups = subject.getPrincipals(GroupPrincipal.class).toArray();
    for (int i = 0; i < groups.length; i++) {
      groupNames.add(((Principal)groups[0]).getName());
    }
    return groupNames;
  }

  protected String getEffectiveUserName(Subject subject) {
    return SubjectUtils.getEffectivePrincipalName(subject);
  }


}
