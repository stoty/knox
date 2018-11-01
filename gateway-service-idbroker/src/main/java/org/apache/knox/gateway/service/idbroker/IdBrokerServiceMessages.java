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

import org.apache.knox.gateway.i18n.messages.Message;
import org.apache.knox.gateway.i18n.messages.MessageLevel;
import org.apache.knox.gateway.i18n.messages.Messages;
import org.apache.knox.gateway.i18n.messages.StackTrace;

@Messages(logger = "org.apache.knox.gateway.service.idbroker")
public interface IdBrokerServiceMessages {

  @Message(level = MessageLevel.ERROR, text = "Unable to get credentials : {0}")
  void logException(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Unable to get credentials for authenticated user {0} because there is no mapped role.")
  void noRoleForUser(String userid);

  @Message(level = MessageLevel.ERROR, text = "Unable to get credentials for authenticated user because the user does not belong to the {0} group.")
  void userNotInGroup(String groupid);

  @Message(level = MessageLevel.ERROR, text = "Unable to get credentials for authenticated user because there is no mapped role for the {0} group.")
  void noRoleForGroup(String groupid);

  @Message(level = MessageLevel.ERROR, text = "Unable to get credentials for authenticated user {0} because there is no mapped role for the associated group(s).")
  void noRoleForGroups(String userid);

  @Message(level = MessageLevel.ERROR, text = "Ambiguous group role mappings for the authenticated user {0} : multiple matching role mappings")
  void multipleMatchingGroupRoles(String userid);

}
