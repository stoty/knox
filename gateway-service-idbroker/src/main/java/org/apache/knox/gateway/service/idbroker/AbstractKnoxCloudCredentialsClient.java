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

import java.io.StringWriter;
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
  protected static final String ROLE_TYPE_USER        = "USER_ROLE";
  protected static final String ROLE_TYPE_GROUP       = "GROUP_ROLE";
  protected static final String ROLE_TYPE_EXPLICIT    = "EXPLICIT_ROLE";
  protected static final String CREDENTIAL_CACHE_TTL  = "credential.cache.ttl";

  private static IdBrokerServiceMessages log = MessagesFactory.get(IdBrokerServiceMessages.class);

  private CloudClientConfigurationProvider cloudConfigProvider;
  protected AliasService aliasService;
  protected CryptoService cryptoService;
  protected String topologyName;

  static final String ERR_NO_ROLE_DEFINED =
      "No suitable role is defined for the authenticated user.";

  static final String ERR_USER_NOT_IN_REQUESTED_GROUP =
      "The authenticated user is not a member of the requested group.";

  static final String ERR_NO_ROLE_FOR_REQUESTED_GROUP =
      "There is no role mapped to the requested group.";

  static final String ERR_USER_NOT_IN_DEFAULT_GROUP =
      "The authenticated user is not a member of the configured default group.";

  static final String ERR_NO_ROLE_FOR_DEFAULT_GROUP =
      "There is no role mapped to the configured default group for the authenticated user.";

  static final String ERR_AMBIGUOUS_GROUP_MAPPINGS =
      "Ambiguous group role mappings for the authenticated user.";

  static final String ERR_NO_MATCHING_GROUP_MAPPINGS =
      "There is no mapped role for the group(s) associated with the authenticated user.";


  // A cache object used to cache credentials. Cache is evicted after 20 mins.
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

  @Override
  public CloudClientConfigurationProvider getConfigProvider() {
    return cloudConfigProvider;
  }

  @Override
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
        if (id != null && isUserMappedToRole(id)) {
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
      throw new WebApplicationException(ERR_NO_ROLE_DEFINED,
                                        Response.status(Response.Status.FORBIDDEN)
                                                .entity(ERR_NO_ROLE_DEFINED)
                                                .build());
    }

    return role;
  }

  /**
   * Get the role mapped to the current user via a user-role mapping.
   *
   * @return The mapped role, or null if there is no matching user-role mapping.
   */
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

  /**
   * Get the role mapped to the specified group identifier
   *
   * @param groupId The group identifier
   *
   * @return The role for the specified group, or null if there is no such mapping.
   */
  protected String getGroupRole(String groupId) {
    String role = null;

    Subject subject = Subject.getSubject(AccessController.getContext());
    if (subject != null) {
      Set<String> groups = getGroupNames(subject);

      CloudClientConfiguration conf = getConfigProvider().getConfig();

      String error = null;

      // If an explicit group is specified, and the authenticated user belongs to that group, get the mapped role
      if (groupId != null) {
        if (groups.contains(groupId)) {
          role = conf.getGroupRole(groupId);
          if (role == null) {
            log.noRoleForGroup(groupId);
            error = generateJSONResponse(ERR_NO_ROLE_FOR_REQUESTED_GROUP, null, groupId);
          }
        } else {
          log.userNotInGroup(groupId);
          error = generateJSONResponse(ERR_USER_NOT_IN_REQUESTED_GROUP, getEffectiveUserName(subject), groupId);
        }
      } else {
        String userName = getEffectiveUserName(subject);

        // Check for a default user-group mapping
        String defaultGroup = conf.getDefaultGroupForUser(userName);
        if (defaultGroup != null) {
          if (groups.contains(defaultGroup)) { // User must be a member of the configured default group
            role = conf.getGroupRole(defaultGroup);
            if (role == null) {
              log.noRoleForGroup(defaultGroup);
              error = generateJSONResponse(ERR_NO_ROLE_FOR_DEFAULT_GROUP, userName, defaultGroup);
            }
          } else {
            log.userNotInGroup(defaultGroup);
            error = generateJSONResponse(ERR_USER_NOT_IN_DEFAULT_GROUP, userName, defaultGroup);
          }
        } else {
          // If there is no default group configured, check all the user's groups for mapped roles.
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
            error = generateJSONResponse(ERR_AMBIGUOUS_GROUP_MAPPINGS, userName, null);
          } else {
            log.noRoleForGroups(userName);
            error = generateJSONResponse(ERR_NO_MATCHING_GROUP_MAPPINGS, userName, null);
          }
        }
      }

      if (error != null) {
        throw new WebApplicationException(error,
            Response.status(Response.Status.FORBIDDEN).entity(error).build());
      }
    }

    return role;
  }

  private String generateJSONResponse(final String errMessage, final String username, final String groupId) {
    StringWriter sw = new StringWriter();

    sw.append("{\n");
    sw.append("\"error\" : \"").append(errMessage).append("\"");
    if (username != null) {
      sw.append(",\n\"auth_id\" : \"").append(username).append("\"");
    }
    if (groupId != null) {
      sw.append(",\n\"group_id\" : \"").append(groupId).append("\"");
    }
    sw.append("\n}\n");

    return sw.toString();
  }

  /**
   * Determine if the user is mapped to the specified role via user- or group-role mappings.
   *
   * @param role The role
   *
   * @return true, if the user is mapped to the specified role; otherwise, false.
   */
  protected boolean isUserMappedToRole(String role) {
    boolean isMapped = false;

    // First, check for a user-role mapping that matches the requested role
    String userRole = getUserRole();
    if (role.equals(userRole)) {
      isMapped = true;
    }

    if (!isMapped) {
      // Check for any of the user's groups for which the mapped role matches the requested role
      Set<String> groups = getGroupNames(Subject.getSubject(AccessController.getContext()));
      for (String group : groups) {
        try {
          if (role.equals(getGroupRole(group))) {
            isMapped = true;
            break;
          }
        } catch (Exception e) {
          // Don't care about groups without role mappings in this case; such "errors" can be ignored
        }
      }
    }

    return isMapped;
  }

  protected Set<String> getGroupNames(Subject subject) {
    Set<String> groupNames = new HashSet<>();
    for (Principal group : subject.getPrincipals(GroupPrincipal.class)) {
      groupNames.add(group.getName());
    }
    log.userGroups(getEffectiveUserName(subject), groupNames);
    return groupNames;
  }

  protected String getEffectiveUserName(Subject subject) {
    return SubjectUtils.getEffectivePrincipalName(subject);
  }
}
