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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.security.GroupPrincipal;
import org.apache.knox.gateway.security.SubjectUtils;
import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.CryptoService;
import org.apache.knox.gateway.services.security.EncryptionResult;

import javax.security.auth.Subject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

public abstract class AbstractKnoxCloudCredentialsClient implements KnoxCloudCredentialsClient {


  protected final static String ROLE_TYPE_USER        = "USER_ROLE";
  protected final static String ROLE_TYPE_GROUP       = "GROUP_ROLE";
  protected final static String ROLE_TYPE_EXPLICIT    = "EXPLICIT_ROLE";
  protected final static String CREDENTIAL_CACHE_TTL  = "credential.cache.ttl";

  private static IdBrokerServiceMessages log = MessagesFactory.get(IdBrokerServiceMessages.class);

  private CloudClientConfigurationProvider cloudConfigProvider = null;
  protected AliasService aliasService;
  protected CryptoService cryptoService;
  protected String topologyName;

  /**
   * A cache object used to cache credentials.
   * Cache is evicted after 20 mins.
   */
  protected Cache<String, EncryptionResult> credentialCache;

  public AbstractKnoxCloudCredentialsClient() {
    super();
  }

  @Override
  public void init(Properties context) {
    topologyName = context.getProperty("topology.name");
    final int ttl = NumberUtils.toInt(context.getProperty(CREDENTIAL_CACHE_TTL), 1200);
    credentialCache =
        CacheBuilder.
            newBuilder().
            maximumSize(1000).
            expireAfterWrite(ttl, TimeUnit.SECONDS).
            recordStats().
            build();
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
  public void setCryptoService(CryptoService cryptoService) {
    this.cryptoService = cryptoService;
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
          role = getGroupRole(id);
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

      CloudClientConfiguration conf = getConfigProvider().getConfig();

      // If an explicit group is specified, and the authenticated user belongs to that group, get the mapped role
      if (id != null) {
        if (groups.contains(id)) {
          role = conf.getGroupRole(id);
          if (role == null) {
            log.noRoleForGroup(id);
          }
        } else {
          log.userNotInGroup(id);
        }
      } else {
        String userName = getEffectiveUserName(subject);

        // First, check for a default user-group mapping
        String defaultGroup = conf.getDefaultGroupForUser(userName);
        if (defaultGroup != null) {
          if (groups.contains(defaultGroup)) { // User must be a member of the configured default group
            role = conf.getGroupRole(defaultGroup);
          }
        }

        // If there is no default group configured, or some other reason why the configured group does not
        // resolve to a role, check all the user's groups for mapped roles
        if (role == null) {
          // Otherwise, check for groups for which there are mapped roles
          List<String> mappedRoles = new ArrayList<>();
          for (String group : groups) {
            String mappedRole = conf.getGroupRole(group);
            if (mappedRole != null) {
              mappedRoles.add(mappedRole);
            }
          }

          // If there is exactly one matching group role mapping, then return that role
          if (mappedRoles.size() == 1) {
            role = mappedRoles.get(0);
          } else if (mappedRoles.size() > 1) {
            // If there is more than one matching group role mapping, then do NOT return a role
            log.multipleMatchingGroupRoles(userName);
          } else {
            log.noRoleForGroups(userName);
          }
        }
      }
    }

    return role;
  }

  protected Set<String> getGroupNames(Subject subject) {
    Set<String> groupNames = new HashSet<>();
    Object[] groups = subject.getPrincipals(GroupPrincipal.class).toArray();
    for (int i = 0; i < groups.length; i++) {
      groupNames.add(((Principal)groups[i]).getName());
    }
    return groupNames;
  }

  protected String getEffectiveUserName(Subject subject) {
    return SubjectUtils.getEffectivePrincipalName(subject);
  }


}
