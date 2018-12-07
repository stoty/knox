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

package org.apache.knox.gateway.cloud.idbroker;

import java.io.IOException;
import java.util.HashMap;

import org.apache.knox.gateway.cloud.idbroker.messages.AuthResponseAWSMessage;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;

public interface IdentityBrokerClient {
	  public enum IDBMethod {
		  DEFAULT, GROUPS_ONLY, SPECIFIC_GROUP, USER_ONLY, SPECIFIC_ROLE
	  }
	  
	/**
	   * Build some AWS credentials from the response.
	   * @param responseAWSStruct parsed JSON response
	   * @return the AWS credentials
	   * @throws IOException failure
	   */
	MarshalledCredentials fromResponse(AuthResponseAWSMessage responseAWSStruct) throws IOException;

	KnoxSession cloudSessionFromDT(String delegationToken) throws IOException;

	KnoxSession cloudSession(HashMap<String, String> headers) throws IOException;

	/**
	   * Fetch the AWS Credentials.
	   * @param session Knox session
	   * @return the credentials.
	   * @throws IOException failure
	   */
	MarshalledCredentials fetchAWSCredentials(KnoxSession session) throws IOException;

	/**
	   * Determine the IDBMethod to call based on config params
	   * @return the method
	   */
	IDBMethod determineIDBMethodToCall();

	/**
	   * Ask for a delegation token.
	   * @param dtSession session
	   * @return the delegation token response
	   * @throws IOException failure.
	   */
	RequestDTResponseMessage requestKnoxDelegationToken(KnoxSession dtSession) throws IOException;

}