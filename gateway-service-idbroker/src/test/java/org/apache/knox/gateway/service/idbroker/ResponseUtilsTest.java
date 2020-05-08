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

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class ResponseUtilsTest {

    @Test
    public void testSimplest() throws Exception {
        final String errorMessage = "Simplest error message";
        String json = ResponseUtils.createErrorResponseJSON(errorMessage);
        logJSON(json);
        Map<String, String> parsed = parseJSON(json);
        assertEquals(1, parsed.size());
        assertEquals(errorMessage, parsed.get("error"));
    }

    @Test
    public void testSimplestAlt() throws Exception {
        final String errorMessage = "Simplest error message";
        final String reason = null;
        String json = ResponseUtils.createErrorResponseJSON(errorMessage, reason);
        logJSON(json);
        Map<String, String> parsed = parseJSON(json);
        assertEquals(1, parsed.size());
        assertEquals(errorMessage, parsed.get("error"));
    }

    @Test
    public void testSimpleWithReason() throws Exception {
        final String errorMessage = "The error message";
        final String reason = "The specific reason";
        String json = ResponseUtils.createErrorResponseJSON(errorMessage, reason);
        logJSON(json);
        Map<String, String> parsed = parseJSON(json);
        assertEquals(2, parsed.size());
        assertEquals(errorMessage, parsed.get("error"));
        assertEquals(reason, parsed.get("reason"));
    }

    @Test
    public void testSimpleAdditionalFields() throws Exception {
        final String errorMessage = "The error message";
        final Map<String, String> fields = new HashMap<>();
        fields.put("field1", "value1");
        fields.put("field2", "value2");
        fields.put("field3", "value3");

        String json = ResponseUtils.createErrorResponseJSON(errorMessage, fields);
        logJSON(json);
        Map<String, String> parsed = parseJSON(json);
        assertEquals(4, parsed.size());
        assertEquals(errorMessage, parsed.get("error"));
        assertEquals(fields.get("field1"), parsed.get("field1"));
        assertEquals(fields.get("field2"), parsed.get("field2"));
        assertEquals(fields.get("field3"), parsed.get("field3"));
    }

    @Test
    public void testSimpleWithReasonAndAdditionalFields() throws Exception {
        final String errorMessage = "The error message";
        final String reason = "The specific reason";
        final Map<String, String> fields = new HashMap<>();
        fields.put("field1", "value1");
        fields.put("field2", "value2");
        fields.put("field3", "value3");

        String json = ResponseUtils.createErrorResponseJSON(errorMessage, reason, fields);
        logJSON(json);
        Map<String, String> parsed = parseJSON(json);
        assertEquals(5, parsed.size());
        assertEquals(errorMessage, parsed.get("error"));
        assertEquals(reason, parsed.get("reason"));
        assertEquals(fields.get("field1"), parsed.get("field1"));
        assertEquals(fields.get("field2"), parsed.get("field2"));
        assertEquals(fields.get("field3"), parsed.get("field3"));
    }

    @Test
    public void testFormattedError() throws Exception {
        final String errorMessageTemplate = "This error message is brought to you by the letter %s and the number %s";
        final String letter = "K";
        final String number = "4";
        String json = ResponseUtils.createErrorResponseJSON(errorMessageTemplate, null, letter, number);
        logJSON(json);
        Map<String, String> parsed = parseJSON(json);
        assertEquals(1, parsed.size());
        assertEquals(String.format(Locale.ROOT, errorMessageTemplate, letter, number), parsed.get("error"));
    }

    @Test
    public void testFormattedErrorWithReason() throws Exception {
        final String errorMessageTemplate = "This error message is brought to you by the letter %s and the number %s";
        final String reason = "This is the reason for the error";
        final String letter = "K";
        final String number = "4";
        String json = ResponseUtils.createErrorResponseJSON(errorMessageTemplate, reason, letter, number);
        logJSON(json);
        Map<String, String> parsed = parseJSON(json);
        assertEquals(2, parsed.size());
        assertEquals(String.format(Locale.ROOT, errorMessageTemplate, letter, number), parsed.get("error"));
        assertEquals(reason, parsed.get("reason"));
    }

    @Test
    public void testFormattedErrorWithAdditionalFields() throws Exception {
        final String errorMessageTemplate = "This error message is brought to you by the letter %s and the number %s";
        final String letter = "K";
        final String number = "4";
        final Map<String, String> fields = new HashMap<>();
        fields.put("fieldA", "valueA");
        fields.put("fieldB", "valueB");
        fields.put("fieldC", "valueC");

        String json = ResponseUtils.createErrorResponseJSON(errorMessageTemplate, null, fields, letter, number);
        logJSON(json);
        Map<String, String> parsed = parseJSON(json);
        assertEquals(4, parsed.size());
        assertEquals(String.format(Locale.ROOT, errorMessageTemplate, letter, number), parsed.get("error"));
        assertEquals(fields.get("fieldA"), parsed.get("fieldA"));
        assertEquals(fields.get("fieldB"), parsed.get("fieldB"));
        assertEquals(fields.get("fieldC"), parsed.get("fieldC"));
    }


    @Test
    public void testFormattedErrorWithReasonAndAdditionalFields() throws Exception {
        final String errorMessageTemplate = "This error message is brought to you by the letter %s and the number %s";
        final String reason = "This is the reason for the error";
        final String letter = "K";
        final String number = "4";
        final Map<String, String> fields = new HashMap<>();
        fields.put("fieldA", "valueA");
        fields.put("fieldB", "valueB");
        fields.put("fieldC", "valueC");

        String json = ResponseUtils.createErrorResponseJSON(errorMessageTemplate, reason, fields, letter, number);
        logJSON(json);
        Map<String, String> parsed = parseJSON(json);
        assertEquals(5, parsed.size());
        assertEquals(String.format(Locale.ROOT, errorMessageTemplate, letter, number), parsed.get("error"));
        assertEquals(reason, parsed.get("reason"));
        assertEquals(fields.get("fieldA"), parsed.get("fieldA"));
        assertEquals(fields.get("fieldB"), parsed.get("fieldB"));
        assertEquals(fields.get("fieldC"), parsed.get("fieldC"));
    }

    private Map<String, String> parseJSON(final String json) throws Exception {
        JsonFactory factory = new JsonFactory();
        ObjectMapper mapper = new ObjectMapper(factory);
        TypeReference<Map<String, String>> typeRef = new TypeReference<Map<String, String>>() {};
        return mapper.readValue(json, typeRef);
    }

    private void logJSON(final String json) {
        System.out.println(json);
    }
}
