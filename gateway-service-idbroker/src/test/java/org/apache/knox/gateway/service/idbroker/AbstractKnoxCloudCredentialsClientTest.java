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
import org.junit.Test;

import javax.security.auth.Subject;
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
  public void testDefaultAlgorithm() {
    Properties config = new Properties();
    config.setProperty("role.user.test_user", "test_user_role");
    config.setProperty("role.group.grp1", "role1");

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
   * For a user, for which no role mapping has been configured, no role should be returned.
   */
  @Test
  public void testUserRole() {
    Properties config = new Properties();
    config.setProperty("role.user.test_user", "test_user_role");

    Subject user = createTestSubject("test_user");

    String role = getUserRole(config, user);
    assertEquals("test_user_role", role);
  }


  /**
   * For a user belonging to multiple groups (for which there are valid role mappings), no role should be returned since
   * the Cloud Access Broker cannot know which one to choose.
   */
  @Test
  public void testNoRoleForUserWithMultipleGroupRoleMappings() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("role.group.grp2", "role2");

    Subject user = createTestSubject("test_user", "grp1", "grp2");

    String role = getGroupRole(config, user);
    assertNull("Expected no role because the user belongs to multiple groups for which there are role mappings", role);
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
    config.setProperty("group.user.test_user", "grp2");

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
    config.setProperty("group.user.test_user", "grp2");

    // User does not belong to the configured default group
    Subject user = createTestSubject("test_user", "grp1", "grp3");

    String role = getGroupRole(config, user);
    assertNull("Expected no role because the default group is invalid, and the user belongs to multiple groups for " +
               "which there are role mappings", role);
  }

  /**
   * For a user belonging to a single group (for which there is a valid role mappings), if the configured default group
   * is not a group to which the user belongs, then the role for the single matching group should be returned.
   */
  @Test
  public void testInvalidDefaultUserGroupConfigWithSingleGroupRoleMapping() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");
    config.setProperty("group.user.test_user", "grp2");

    // User does not belong to the configured default group
    Subject user = createTestSubject("test_user", "grp1", "grp3");

    String role = getGroupRole(config, user);
    assertNotNull("Even though the default group configured for the user is invalid, " +
                  "expected the role for single the matching group role mapping", role);
    assertEquals("role1", role);
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

    String role = getGroupRole(config, user, "grp3");
    assertNull("Expected no role because the user does not belong to the specified group", role);
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

    // User belongs to the explicitly requested group, but there is no group-role mapping
    Subject user = createTestSubject("test_user", "grp1", "grp2", "grp3");

    String role = getGroupRole(config, user, "grp3");
    assertNull("Expected no role because there is no role mapped to the specified group", role);
  }


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
   * For a valid group role mapping, a request for that mapped role should succeed if the user belongs to that group.
   */
  @Test
  public void testExplicitGroupMappedRole() {
    Properties config = new Properties();
    config.setProperty("role.group.grp1", "role1");

    // User belongs to the explicitly requested group, and there is a corresponding group-role mapping
    Subject user = createTestSubject("test_user", "grp1", "grp2", "grp3");

    String role = getExplicitRole(config, user, "role1");
    assertNotNull("Expected the specified role", role);
    assertEquals("Expected the requested role because the user belongs to a single group to which it is mapped",
                 "role1",
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

    // User belongs to the explicitly requested group, but there is no group-role mapping
    Subject user = createTestSubject("test_user", "grp2", "grp3");

    String role = getExplicitRole(config, user, "role1");
    assertNull("Expected no role because the user does not belong to the group to which the requested role is mapped",
               role);
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
          user.doAs(user,
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
        user.doAs(user,
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
        user.doAs(user,
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
          user.doAs(user,
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


  /**
   * An extension of AbstractKnoxCloudCredentialsClient that allows for testing the common functionality of all derived
   * KnoxCloudCredentialsClient implementations.
   */
  private static final class TestableKnoxCloudCredentialsClient extends AbstractKnoxCloudCredentialsClient {

    TestableKnoxCloudCredentialsClient(Properties config) {
      CloudClientConfigurationProvider configProvider = new DefaultCloudClientConfigurationProvider();
      configProvider.init(config);
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
