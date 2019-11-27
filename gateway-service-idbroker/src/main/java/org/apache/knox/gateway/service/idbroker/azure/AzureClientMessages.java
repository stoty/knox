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
package org.apache.knox.gateway.service.idbroker.azure;

import org.apache.knox.gateway.i18n.messages.Message;
import org.apache.knox.gateway.i18n.messages.MessageLevel;
import org.apache.knox.gateway.i18n.messages.Messages;
import org.apache.knox.gateway.i18n.messages.StackTrace;

@Messages(logger = "org.apache.knox.gateway.service.idbroker.azure")
public interface AzureClientMessages {

  @Message(level = MessageLevel.ERROR, text = "Error fetching credentials for role {0} from cache reason: {1}")
  void cacheException(String role, String error);

  @Message(level = MessageLevel.ERROR, text = "Missing alias {0} required for Cloud Access Broker.")
  void aliasConfigurationError(String alias);

  @Message(level = MessageLevel.ERROR, text = "Azure ADLS2 credentials client error : {0}")
  void exception(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Azure ADLS2 credentials client configuration error : {0}")
  void configError(String message);

  @Message(level = MessageLevel.ERROR, text = "Azure ADLS2, error obtaining access token, cause : {0}")
  void accessTokenGenerationError(String message);

  @Message(level = MessageLevel.ERROR, text = "Error parsing response from URL: {0}")
  void responseError(String message);

  @Message(level = MessageLevel.ERROR,
           text = "Error attaching identities to VM: {0}")
  void attachIdentitiesError(String message);

  @Message(level = MessageLevel.ERROR,
           text = "Request to attach identities to VM failed with response code {0}, message: {1}")
  void attachIdentitiesError(int statusCode, String message);

  @Message(level = MessageLevel.DEBUG,
           text = "Calling HTTP method {0} on URL {1}")
  void printRequestURL(String method, String url);

  @Message(level = MessageLevel.DEBUG, text = "System MSI resource name: {0}")
  void printSystemMSIResourceName(String resource);

  @Message(level = MessageLevel.INFO, text = "Found {0} user assigned MSIs in topology {1}")
  void foundUserMSI(int no, String topologyName);

  @Message(level = MessageLevel.INFO, text = "Identities Attached: {0}")
  void attachIdentitiesSuccess(String ids);

  @Message(level = MessageLevel.ERROR, text = "Done retrying, unable to attach identities or Azure is taking time to update identities.")
  void attachIdentitiesFailure();

  @Message(level = MessageLevel.DEBUG, text = "Using user MSI {0} to get token")
  void usingMSIResource(String resource);

  @Message(level = MessageLevel.DEBUG, text = "Using principal {0} to get token")
  void usingPrincipalResource(String resource);

  @Message(level = MessageLevel.INFO, text = "Retrying ... {0}, checking whether user assigned MSIs are assigned to IDB VM. ")
  void retryCheckAssignedMSI(int retryCount);

  @Message(level = MessageLevel.ERROR,
           text = "Error attempting to check attached user assigned identities, reason {0}")
  void retrievedIdentitiesError(String message);

  @Message(level = MessageLevel.DEBUG, text = "HTTP Response: {0}")
  void printHttpResponse(String response);

  @Message(level = MessageLevel.INFO, text = "Getting new tokens for attached identities {0}, before attaching new identity/s")
  void forceUpdateCachedTokens(String identities);

  @Message(level = MessageLevel.ERROR,
           text = "Mapped identity \"{0}\" is not a valid MSI, skipping attaching it to the VM")
  void notValidMSISkipAttachment(String id);

  @Message(level = MessageLevel.DEBUG, text = "Retrieved identity list from Azure matches identities in IDB config, size {0}")
  void retrievedIdentityListMatches(int size);

  @Message(level = MessageLevel.INFO, text = "Retrieved identity list ( {0} ) from Azure does not match identities in IDB config ( {1} )")
  void retrievedIdentityListNoMatches(int remote, int local);

  @Message(level = MessageLevel.ERROR,
           text = "Failed to get access token for MSI {0}, retry count {1}")
  void failedRetryMSIaccessToken(String msi, int count);

  @Message(level = MessageLevel.DEBUG, text = "Identities already attached.")
  void identitiesAlreadyAttached();

  @Message(level = MessageLevel.ERROR,  text = "Assumer identity \"{0}\" is not a valid MSI")
  void invalidAssumerMSI(String msi);

  @Message(level = MessageLevel.ERROR,  text = "Assumer identity not found, make sure property 'azure.vm.assumer.identity' is set.")
  void noAssumerIdentityConfigured();

  @Message(level = MessageLevel.INFO,  text = "Token for role {0} is expired in cache, attempting to get a new one")
  void cacheTokenExpired(String role);

  @Message(level = MessageLevel.ERROR,  text = "Error while retrying to get expired cached token for role {0}, error: {1}")
  void cacheTokenRetryError(String role, String error);

  @Message(level = MessageLevel.DEBUG,  text = "Token time {0}, current time {1}")
  void recordTokenExpiryTime(String tokenTime, String currentTime);
}
