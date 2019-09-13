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
package org.apache.knox.gateway.service.idbroker;

import org.apache.knox.gateway.security.GroupPrincipal;
import org.apache.knox.gateway.security.PrimaryPrincipal;
import org.eclipse.jetty.http.HttpStatus;
import org.junit.Test;

import javax.security.auth.Subject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.io.StringWriter;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Properties;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;


public class AbstractKnoxCloudCredentialsClientTest {

  /**
   * The default algorithm for resolving role mappings prefers a user mapping to any group mapping because it is more
   * specific.
   */
  @Test
  public void testDefaultAlgorithmPreferUserMapping() {
    Properties config = new Properties();
    config.setProperty("role.user.test_user", "test_user_role");
    config.setProperty("role.group.grp1", "role1");

    // The user belongs to a group for which there is a valid role mapping, but the user mapping should be preferred
    Subject user = createTestSubject("test_user", "grp1", "grp2");

    String role = getRole(config, user);
    assertNotNull("Expected a role because the user is mapped to a role", role);
    assertEquals("Expected the role mapped to the user since this should be preferred to any valid group mapping",
                 "test_user_role",
                 role);
  }

  /**
   * The default algorithm for resolving role mappings should reference group mappings when there is no user mapping.
   */
  @Test
  public void testDefaultAlgorithmOnlyGroupMapping() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");

    // The user belongs to a single group for which there is a role mapping
    Subject user = createTestSubject("test_user", "grp1", "grp2");

    String role = getRole(config, user);
    assertNotNull("Expected a role because the user is mapped to a role", role);
    assertEquals("Expected the role mapped to the user since this should be preferred to any valid group mapping",
                 "role1",
                 role);
  }


  /**
   * For a user, for which no role mapping has been configured, no role should be returned.
   */
  @Test
  public void testUserRoleNoUserMapping() {
    Properties config = new Properties();

    Subject user = createTestSubject("test_user");

    String role = getUserRole(config, user);
    assertNull("Expected no role because there is no user-role mapping configured", role);
  }


  /**
   * For a user, for which a user-role mapping has been configured, the mapped role should be returned.
   */
  @Test
  public void testUserRole() {
    Properties config = new Properties();
    config.setProperty("role.user.test_user", "test_user_role");

    Subject user = createTestSubject("test_user");

    String role = getUserRole(config, user);
    assertEquals("Expected the role mapped to the user identifier", "test_user_role", role);
  }

  /**
   * For a user belonging to multiple groups (for which there are valid role mappings), no role should be returned since
   * the Cloud Access Broker cannot know which one to choose.
   */
  @Test
  public void testNoRoleForUserWithMultipleMatchingGroupRoleMappings() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("role.group.grp2", "role2");

    Subject user = createTestSubject("test_user", "grp1", "grp2");

    final String expectedResponseMsg =
        generateExpectedResponseMessage(AbstractKnoxCloudCredentialsClient.ERR_AMBIGUOUS_GROUP_MAPPINGS,
                                        "test_user",
                                        null);
    doTestInvalidGroupConfig(config, user, expectedResponseMsg);
  }

  /**
   * For a user belonging to multiple groups (for which there are valid role mappings), a role
   * should be returned if all the groups map to the same role since the Cloud Access Broker
   * knew there was only one role.
   */
  @Test
  public void testRoleForUserWithMultipleMatchingGroupRoleMappings() {
    String roleName = "role1";
    Properties config = new Properties();
    config.setProperty("role.group.grp1", roleName);
    config.setProperty("role.group.grp2", roleName);

    Subject user = createTestSubject("test_user", "grp1", "grp2");

    String determinedRole = getGroupRole(config, user);
    assertNotNull("Expected the role for the configured default group", determinedRole);
    assertEquals(roleName, determinedRole);
  }

  /**
   * For a user, for which none of the associated groups is mapped to any role, no role should be returned when the
   * request is based on group membership.
   */
  @Test
  public void testNoMatchingGroupRoleMappingsForGroupRoleRequest() {
    Properties config = new Properties();

    // User does not belong to the configured default group, but does belong to the single group for which there is a
    // role mapping
    Subject user = createTestSubject("test_user", "grp1", "grp2");

    final String expectedResponseMsg =
        generateExpectedResponseMessage(AbstractKnoxCloudCredentialsClient.ERR_NO_MATCHING_GROUP_MAPPINGS,
                                        "test_user",
                                        null);
    doTestInvalidGroupConfig(config, user, expectedResponseMsg);
  }

  /**
   * CDPD-291
   *
   * For a user belonging to multiple groups (for which there are valid role mappings), the role can be resolved if
   * there is a default group configured for the user.
   */
  @Test
  public void testDefaultUserGroupConfig() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("role.group.grp2", "role2");
    config.setProperty("group.user.test_user", "grp2"); // default user group config

    // User belongs to multiple groups with group-role mappings
    Subject user = createTestSubject("test_user", "grp1", "grp2");

    String role = getGroupRole(config, user);
    assertNotNull("Expected the role for the configured default group", role);
    assertEquals("role2", role);
  }

  /**
   * For a user belonging to multiple groups (for which there are valid role mappings), the role can be resolved if
   * there is a default group configured for the user. However, if the configured default group is not a group to which
   * the user belongs, then no role should be returned because the Cloud Access Broker cannot know which one to choose.
   */
  @Test
  public void testInvalidDefaultUserGroupConfigWithMultipleGroupRoleMappings() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("role.group.grp2", "role2");
    config.setProperty("role.group.grp3", "role3");
    config.setProperty("group.user.test_user", "grp2"); // default user group config

    // User does not belong to the configured default group
    Subject user = createTestSubject("test_user", "grp1", "grp3");

    final String expectedResponseMsg =
        generateExpectedResponseMessage(AbstractKnoxCloudCredentialsClient.ERR_USER_NOT_IN_DEFAULT_GROUP,
                                        "test_user",
                                        "grp2");
    doTestInvalidGroupConfig(config, user, expectedResponseMsg);
  }

  /**
   * For a user belonging to a single group (for which there is a valid role mappings), if the configured default group
   * is not a group to which the user belongs, then no role should be returned, even if there is a single matching
   * group-role mapping.
   */
  @Test
  public void testInvalidDefaultUserGroupConfigWithSingleGroupRoleMapping() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("group.user.test_user", "grp2");

    // User does not belong to the configured default group, but does belong to the single group for which there is a
    // role mapping
    Subject user = createTestSubject("test_user", "grp1", "grp3");

    final String expectedResponseMsg =
        generateExpectedResponseMessage(AbstractKnoxCloudCredentialsClient.ERR_USER_NOT_IN_DEFAULT_GROUP,
                                        "test_user",
                                        "grp2");
    doTestInvalidGroupConfig(config, user, expectedResponseMsg);
  }

  /**
   * For a user, for whom there is a configured default group (to which the user belongs), if there is no role mapping
   * for that default group, then no role should be returned.
   */
  @Test
  public void testInvalidDefaultUserGroupConfigWithNoGroupRoleMapping() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("group.user.test_user", "grp2"); // default user group config

    // User does not belong to the configured default group
    Subject user = createTestSubject("test_user", "grp2", "grp1");

    final String expectedResponseMsg =
        generateExpectedResponseMessage(AbstractKnoxCloudCredentialsClient.ERR_NO_ROLE_FOR_DEFAULT_GROUP,
                                        "test_user",
                                        "grp2");
    doTestInvalidGroupConfig(config, user, expectedResponseMsg);
  }

  /**
   * For a user belonging to multiple groups (for which there are valid role mappings), if a
   * group (to which the user belongs) is explicitly specified, then the role mapped to that group should be returned.
   */
  @Test
  public void testUserGroupWithMultipleGroupRoleMappingsAndExplicitGroupRequest() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("role.group.grp2", "role2");

    Subject user = createTestSubject("test_user", "grp1", "grp2");

    String role = getGroupRole(config, user, "grp2");
    assertNotNull("Expected the role for specified group role mapping", role);
    assertEquals("role2", role);
  }

  /**
   * For a user belonging to multiple groups (for which there are valid role mappings), if a
   * group (to which the user does NOT belong) is explicitly specified, then no role should be returned because the
   * Cloud Access Broker cannot know which one to choose.
   */
  @Test
  public void testUserGroupWithMultipleGroupRoleMappingsAndUserNotInExplicitGroup() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("role.group.grp2", "role2");
    config.setProperty("role.group.grp3", "role3");

    // User does not belong to the explicitly requested group
    Subject user = createTestSubject("test_user", "grp1", "grp2");

    final String expectedResponseMsg =
        generateExpectedResponseMessage(AbstractKnoxCloudCredentialsClient.ERR_USER_NOT_IN_REQUESTED_GROUP,
                                        "test_user",
                                        "grp3");
    doTestInvalidGroupConfig(config, user, "grp3", expectedResponseMsg);
  }


  /**
   * For a user belonging to multiple groups (for which there are valid role mappings), if a
   * group (to which the user belongs) is explicitly specified, but there is no role mapped to that group,
   * then no role should be returned.
   */
  @Test
  public void testUserGroupWithMultipleGroupRoleMappingsAndExplicitGroupNotMapped() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("role.group.grp2", "role2");

    // User belongs to the explicitly requested group, but there is no corresponding group-role mapping
    Subject user = createTestSubject("test_user", "grp1", "grp2", "grp3");

    final String expectedResponseMsg =
        generateExpectedResponseMessage(AbstractKnoxCloudCredentialsClient.ERR_NO_ROLE_FOR_REQUESTED_GROUP,
                                        null,
                                        "grp3");
    doTestInvalidGroupConfig(config, user, "grp3", expectedResponseMsg);
  }


  /**
   * For a user, for which there are no user or group role mappings, a request for a specific role should fail because
   * the requested role is not associated with the user in any way.
   */
  @Test
  public void testInvalidExplicitUserMappedRole() {
    Properties config = new Properties();

    Subject user = createTestSubject("test_user", "grp1", "grp2", "grp3");

    String role = getExplicitRole(config, user, "arbitrary_role");
    assertNull("Expected no role because the user is not mapped to the specified role in any way.", role);
  }


  /**
   * For a user, for which there is a user-role mapping, a request for that mapped role should succeed.
   */
  @Test
  public void testExplicitUserMappedRole() {
    Properties config = new Properties();
    config.setProperty("role.user.test_user", "test_user_role");

    Subject user = createTestSubject("test_user", "grp1", "grp2", "grp3");

    String role = getExplicitRole(config, user, "test_user_role");
    assertNotNull("Expected the specified role", role);
    assertEquals("Expected the requested role because the user is explicitly mapped to it.", "test_user_role", role);
  }


  /**
   * For a user, for which there is a user-role mapping and group-role mapping(s), a request for that mapped role
   * should succeed.
   */
  @Test
  public void testExplicitUserMappedRoleWithUserAndGroupMappings() {
    Properties config = new Properties();
    config.setProperty("role.user.test_user", "test_user_role");
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("role.group.grp3", "role3");

    Subject user = createTestSubject("test_user", "grp1", "grp2", "grp3");

    String role = getExplicitRole(config, user, "test_user_role");
    assertNotNull("Expected the specified role", role);
    assertEquals("Expected the requested role because the user is explicitly mapped to it.", "test_user_role", role);
  }


  /**
   * For a valid group role mapping, a request for that mapped role should succeed if the user belongs to that group.
   */
  @Test
  public void testExplicitGroupMappedRole() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");

    // User belongs to the group mapped to the explicitly requested role
    Subject user = createTestSubject("test_user", "grp1", "grp2", "grp3");

    String role = getExplicitRole(config, user, "role1");
    assertNotNull("Expected the specified role", role);
    assertEquals("Expected the requested role because the user belongs to a single group to which it is mapped",
                 "role1",
                 role);
  }


  /**
   * For a user who belongs to multiple groups, but for whom only one of those groups is mapped to a role, if that
   * mapped role is explicitly requested, but the mapped group is not the first in the list, then the role should still
   * be resolved correctly.
   *
   * CDPD-766
   */
  @Test
  public void testExplicitGroupMappedRole_CDPD_766() {
    final String roleName = "theRole";
    Properties config = new Properties();
    config.setProperty("role.group.grp3", roleName);

    // User belongs to the group mapped to the explicitly requested role, but there are other groups evaluated first
    Subject user = createTestSubject("test_user", "grp1", "grp2", "grp3");

    String role = getExplicitRole(config, user, roleName);
    assertNotNull("Expected the specified role", role);
    assertEquals("Expected the requested role because the user belongs to a single group to which it is mapped",
                 roleName,
                 role);
  }


  /**
   * For a valid group role mapping, a request for that mapped role should succeed if the user belongs to that group,
   * even if there is also a valid user-role mapping.
   */
  @Test
  public void testExplicitGroupMappedRoleWithUserAndGroupMappings() {
    Properties config = new Properties();
    config.setProperty("test_user", "test_user_role");
    config.setProperty("role.group.grp1", "role1");

    // User belongs to the group mapped to the explicitly requested role
    Subject user = createTestSubject("test_user", "grp1", "grp2", "grp3");

    String role = getExplicitRole(config, user, "role1");
    assertNotNull("Expected the specified role", role);
    assertEquals("Expected the requested role because the user belongs to a single group to which it is mapped",
        "role1",
        role);
  }


  /**
   * BUG-119482
   *
   * For multiple valid group role mappings, a request for an explicit role should succeed if any of the user's
   * group-role mappings matches (i.e., user belongs to a group mapped to the role) that requested role.
   */
  @Test
  public void testExplicitGroupMappedRoleWithMultipleGroupMappings() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("role.group.grp2", "role2");

    // User belongs to a group mapped to the explicitly requested role, plus additional group(s) with role mapping
    Subject user = createTestSubject("test_user", "grp1", "grp2", "grp3");

    String role = getExplicitRole(config, user, "role2");
    assertNotNull("Expected the requested role", role);
    assertEquals("Expected the requested role because the user belongs to a group for which it is mapped",
                 "role2",
                 role);
  }


  /**
   * For a valid group role mapping, a request for that mapped role should fail if the user does not belong to that
   * group.
   */
  @Test
  public void testInvalidExplicitGroupMappedRole() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("role.group.grp2", "role2");

    // User does not belong to the group mapped to the explicitly requested role
    Subject user = createTestSubject("test_user", "grp2", "grp3");

    String role = getExplicitRole(config, user, "role1");
    assertNull("Expected no role because the user does not belong to the group to which the requested role is mapped",
               role);
  }


  /**
   * Negative test for a group role lookup for a user.
   *
   * @param config The Cloud Access Broker configuration properties
   * @param user   A Subject representing the authenticated user.
   * @param expectedResponseMsg The error message expected in the response.
   */
  private void doTestInvalidGroupConfig(final Properties config, final Subject user, final String expectedResponseMsg) {
    doTestInvalidGroupConfig(config, user, null, expectedResponseMsg);
  }


  /**
   * Negative test for a group role lookup for a user.
   *
   * @param config The Cloud Access Broker configuration properties
   * @param user   A Subject representing the authenticated user.
   * @param group  A group identifier to use for resolving the associated role.
   * @param expectedResponseMsg The error message expected in the response.
   */
  private void doTestInvalidGroupConfig(final Properties config,
                                        final Subject user,
                                        final String group,
                                        final String expectedResponseMsg) {
    try {
      getGroupRole(config, user, group);
    } catch (WebApplicationException e) {
      Response response = e.getResponse();
      assertEquals(HttpStatus.FORBIDDEN_403, response.getStatus());
      assertEquals(expectedResponseMsg, response.getEntity());
    }
  }


  /**
   * Get a role from the test KnoxCloudCredentialsClient, based on the provided configuration and user, using the
   * default algorithm.
   *
   * @param config The Cloud Access Broker configuration properties
   * @param user   A Subject representing the authenticated user.
   *
   * @return The resolved role, or null if none could be resolved.
   */
  private String getRole(final Properties config, final Subject user) {
    String result = null;
    try {
      result =
          Subject.doAs(user,
                    (PrivilegedAction<String>) () -> (new TestableKnoxCloudCredentialsClient(config)).getRole());
    } catch (Exception e) {
      //
    }
    return result;
  }



  /**
   * Get a user role from the test KnoxCloudCredentialsClient, based on the provided configuration and user.
   *
   * @param config The Cloud Access Broker configuration properties
   * @param user   A Subject representing the authenticated user.
   *
   * @return The resolved role, or null if none could be resolved.
   */
  private String getUserRole(final Properties config, final Subject user) {
    return
        Subject.doAs(user,
            (PrivilegedAction<String>) () -> (new TestableKnoxCloudCredentialsClient(config)).getUserRole());
  }


  /**
   * Get a group role from the test KnoxCloudCredentialsClient, based on the provided configuration and user.
   *
   * @param config The Cloud Access Broker configuration properties
   * @param user   A Subject representing the authenticated user.
   *
   * @return The resolved role, or null if none could be resolved.
   */
  private String getGroupRole(final Properties config, final Subject user) {
    return getGroupRole(config, user, null);
  }


  /**
   * Get a group role from the test KnoxCloudCredentialsClient, based on the provided configuration and user.
   *
   * @param config The Cloud Access Broker configuration properties
   * @param user   A Subject representing the authenticated user.
   * @param group  The explicit group for which the role should be resolved.
   *
   * @return The resolved role, or null if none could be resolved.
   */
  private String getGroupRole(final Properties config, final Subject user, final String group) {
    return
        Subject.doAs(user,
            (PrivilegedAction<String>) () -> (new TestableKnoxCloudCredentialsClient(config)).getGroupRole(group));
  }


  /**
   * Get the explicitly specified role from the test KnoxCloudCredentialsClient, based on the provided configuration
   * and user.
   *
   * @param config The Cloud Access Broker configuration properties
   * @param user   A Subject representing the authenticated user.
   * @param role   The explicit role to request.
   *
   * @return The resolved role, or null if none could be resolved.
   */
  private String getExplicitRole(final Properties config, final Subject user, final String role) {
    final String roleType = AbstractKnoxCloudCredentialsClient.ROLE_TYPE_EXPLICIT;

    String result = null;
    try {
      result =
          Subject.doAs(user,
              (PrivilegedAction<String>) () -> (new TestableKnoxCloudCredentialsClient(config)).getRole(roleType, role));
    } catch (Exception e) {
      //
    }
    return result;
  }


  /**
   * Create a Subject for testing.
   *
   * @param username The user identifier
   * @param groups   Zero or more groups to which the user belongs.
   *
   * @return A Subject
   */
  private Subject createTestSubject(final String username, final String...groups) {
    Subject s = new Subject();

    Set<Principal> principals = s.getPrincipals();
    principals.add(new PrimaryPrincipal(username));

    for (String group : groups) {
      principals.add(new GroupPrincipal(group));
    }

    return s;
  }

  private String generateExpectedResponseMessage(final String error, final String user, final String group) {
    StringWriter sw = new StringWriter();

    sw.append("{\n");
    sw.append("\"error\" : \"").append(error).append("\"");
    if (user != null) {
      sw.append(",\n\"auth_id\" : \"").append(user).append("\"");
    }
    if (group != null) {
      sw.append(",\n\"group_id\" : \"").append(group).append("\"");
    }
    sw.append("\n}\n");

    return sw.toString();
  }

  /**
   * An extension of AbstractKnoxCloudCredentialsClient that allows for testing the common functionality of all derived
   * KnoxCloudCredentialsClient implementations.
   */
  private static final class TestableKnoxCloudCredentialsClient extends AbstractKnoxCloudCredentialsClient {
    TestableKnoxCloudCredentialsClient(Properties properties) {
      CloudClientConfigurationProvider configProvider = new DefaultCloudClientConfigurationProvider();
      configProvider.init(null, properties);
      setConfigProvider(configProvider);
    }

    @Override
    public String getName() {
      return null;
    }

    @Override
    public Object getCredentials() {
      return null;
    }

    @Override
    public Object getCredentialsForRole(String role) {
      return null;
    }
  }

}
