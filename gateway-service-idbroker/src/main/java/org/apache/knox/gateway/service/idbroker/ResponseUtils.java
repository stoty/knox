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

import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

public class ResponseUtils {

    /**
     * Create consistently-formatted JSON for the specified response error message.
     *
     * @param errorMessageTemplate The template for the error description
     * @param reason               Optional error detail
     * @param args                 Error message template arguments
     *
     * @return A formatted JSON String.
     */
    public static String createErrorResponseJSON(final String errorMessageTemplate,
                                                 final String reason,
                                                 final Object...args) {
        StringBuilder responseTemplateBuilder = new StringBuilder("{\n  \"error\": \"").append(errorMessageTemplate)
                                                                                       .append("\"");

        if (reason != null && !reason.isEmpty()) {
            responseTemplateBuilder.append(",\n  \"reason\": \"")
                                   .append(reason)
                                   .append('\"');
        }

        responseTemplateBuilder.append("\n}\n");

        return format(responseTemplateBuilder.toString(), args);
    }

    public static String createErrorResponseJSON(final String              errorMessageTemplate,
                                                 final String              reason,
                                                 final Map<String, String> fields,
                                                 final Object...           messageTemplateArgs) {
        StringBuilder responseTemplateBuilder =
            new StringBuilder("{\n  \"error\": \"").append(errorMessageTemplate).append("\"");

        if (reason != null && !reason.isEmpty()) {
            responseTemplateBuilder.append(",\n  \"reason\": \"").append(reason).append('\"'); // TODO: PJZ: Can reason be just another field?
        }

        if (fields != null && !fields.isEmpty()) {
            responseTemplateBuilder.append(",\n");

            Iterator<Map.Entry<String, String>> fieldIter = fields.entrySet().iterator();
            while (fieldIter.hasNext()) {
                Map.Entry<String, String> field = fieldIter.next();
                responseTemplateBuilder.append("  \"")
                        .append(field.getKey())
                        .append("\": \"")
                        .append(field.getValue())
                        .append('\"');
                if (fieldIter.hasNext()) {
                    responseTemplateBuilder.append(",\n");
                }
            }
        }

        responseTemplateBuilder.append("\n}\n");

        return format(responseTemplateBuilder.toString(), messageTemplateArgs);
    }

    public static String format(final String template, final Object...args) {
        return String.format(Locale.ROOT, template, args);
    }

}
