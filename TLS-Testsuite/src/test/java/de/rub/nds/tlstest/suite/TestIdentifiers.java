/*
 * Copyright 2024 marcel.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlstest.suite;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.anvilcore.teststate.reporting.MetadataFetcher;
import java.lang.reflect.Method;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;

public class TestIdentifiers {

    /** Checks whether any test ids are missing, duplicate or too much in the metadata file. */
    @Test
    public void idsRegistered() {
        Reflections reflections =
                new Reflections("de.rub.nds.tlstest", new MethodAnnotationsScanner());
        Set<Method> nonCombinatorialMethods =
                reflections.getMethodsAnnotatedWith(NonCombinatorialAnvilTest.class);
        Set<Method> combinatorialMethods = reflections.getMethodsAnnotatedWith(AnvilTest.class);
        MetadataFetcher metadataFetcher = new MetadataFetcher();
        Set<String> registeredIds = metadataFetcher.getAllTestIds();
        List<String> processedIds = new LinkedList<>();
        for (Method combinatorialMethod : combinatorialMethods) {
            checkId(
                    combinatorialMethod.getAnnotation(AnvilTest.class).id(),
                    combinatorialMethod,
                    registeredIds,
                    processedIds);
        }
        for (Method nonCombinatorialMethod : nonCombinatorialMethods) {
            checkId(
                    nonCombinatorialMethod.getAnnotation(NonCombinatorialAnvilTest.class).id(),
                    nonCombinatorialMethod,
                    registeredIds,
                    processedIds);
        }
        for (String registeredId : registeredIds) {
            assertTrue(
                    processedIds.contains(registeredId),
                    "TestId '"
                            + registeredId
                            + "' is registered in metadata but not referenced by any test");
        }
    }

    private void checkId(
            String testId, Method method, Set<String> registeredIds, List<String> processedIds) {
        assertNotNull(
                testId,
                "Test method "
                        + method.getDeclaringClass()
                        + "."
                        + method
                        + " has a TestId of null.");
        assertFalse(
                testId.isEmpty(),
                "Test method "
                        + method.getDeclaringClass()
                        + "."
                        + method
                        + " has an empty TestId.");
        assertTrue(
                registeredIds.contains(testId),
                "TestId '" + testId + "' is not registered in metadata file.");
        assertFalse(
                processedIds.contains(testId),
                "TestId '" + testId + "' appears twice in test suite.");
        processedIds.add(testId);
    }
}
