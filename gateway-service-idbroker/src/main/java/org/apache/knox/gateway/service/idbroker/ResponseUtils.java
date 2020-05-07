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

import java.util.Collections;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

public class ResponseUtils {

    /**
     * Create consistently-formatted JSON for the specified response error message.
     *
     * @param errorMessage The error message.
     *
     * @return Formatted JSON error response content.
     */
    public static String createErrorResponseJSON(final String errorMessage) {
        return createErrorResponseJSON(errorMessage, (String) null);
    }

    /**
     * Create consistently-formatted JSON for the specified response error message.
     *
     * @param errorMessage The error message.
     * @param reason       An optional reason message, describing the top-level error message in more detail. May be null.
     *
     * @return Formatted JSON error response content.
     */
    public static String createErrorResponseJSON(final String errorMessage, final String reason) {
        return createErrorResponseJSON(errorMessage, reason, Collections.emptyMap());
    }

    /**
     * Create consistently-formatted JSON for the specified response error message.
     *
     * @param errorMessage The error message.
     * @param fields       Zero or more additional response fields.
     *
     * @return Formatted JSON error response content.
     */
    public static String createErrorResponseJSON(final String errorMessage, final Map<String, String> fields) {
        return createErrorResponseJSON(errorMessage, null, fields);
    }

    /**
     * Create consistently-formatted JSON for the specified response error message.
     *
     * @param errorMessageTemplate A template for the top-level error message.
     * @param reason               An optional reason message, describing the top-level error message in more detail. May be null.
     * @param messageTemplateArgs  Zero or more arguments necessary for formatting the top-level error message template.
     *
     * @return Formatted JSON error response content.
     */
    public static String createErrorResponseJSON(final String   errorMessageTemplate,
                                                 final String   reason,
                                                 final Object...messageTemplateArgs) {
        return createErrorResponseJSON(format(errorMessageTemplate, messageTemplateArgs), reason);
    }

    /**
     *
     * @param errorMessageTemplate A template for the top-level error message.
     * @param reason               An optional reason message, describing the top-level error message in more detail. May be null.
     * @param fields               Zero or more additional response fields.
     * @param messageTemplateArgs  Zero or more arguments necessary for formatting the top-level error message template.
     *
     * @return Formatted JSON error response content.
     */
    public static String createErrorResponseJSON(final String              errorMessageTemplate,
                                                 final String              reason,
                                                 final Map<String, String> fields,
                                                 final Object...           messageTemplateArgs) {
        return createErrorResponseJSON(format(errorMessageTemplate, messageTemplateArgs), reason, fields);
    }

    /**
     *
     * @param error  The top-level error message.
     * @param reason An optional reason message, describing the top-level error message in more detail. May be null.
     * @param fields Zero or more additional response message fields.
     *
     * @return Formatted JSON error response content.
     */
    public static String createErrorResponseJSON(final String              error,
                                                 final String              reason,
                                                 final Map<String, String> fields) {
        StringBuilder responseBuilder =
                new StringBuilder("{\n  \"error\": \"").append(error).append("\"");

        if (reason != null && !reason.isEmpty()) {
            responseBuilder.append(",\n  \"reason\": \"").append(reason).append('\"');
        }

        if (fields != null && !fields.isEmpty()) {
            responseBuilder.append(",\n");

            Iterator<Map.Entry<String, String>> fieldIter = fields.entrySet().iterator();
            while (fieldIter.hasNext()) {
                Map.Entry<String, String> field = fieldIter.next();
                responseBuilder.append("  \"")
                               .append(field.getKey())
                               .append("\": \"")
                               .append(field.getValue())
                               .append('\"');
                if (fieldIter.hasNext()) {
                    responseBuilder.append(",\n");
                }
            }
        }

        responseBuilder.append("\n}\n");

        return responseBuilder.toString();
    }

    public static String format(final String template, final Object...args) {
        return String.format(Locale.ROOT, template, args);
    }

}
