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

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.anvilcore.teststate.reporting.MetadataFetcher;
import java.lang.reflect.Method;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.junit.Assert;
import org.junit.Test;
import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;

public class TestIdentifiers {
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
                    registeredIds,
                    processedIds);
        }
        for (Method nonCombinatorialMethod : nonCombinatorialMethods) {
            checkId(
                    nonCombinatorialMethod.getAnnotation(NonCombinatorialAnvilTest.class).id(),
                    registeredIds,
                    processedIds);
        }
        for (String registeredId : registeredIds) {
            Assert.assertTrue(
                    "Test ID "
                            + registeredId
                            + " is registered in metadata but not referenced by any test",
                    processedIds.contains(registeredId));
        }
    }

    private void checkId(String testId, Set<String> registeredIds, List<String> processedIds) {
        Assert.assertTrue(
                "TestID " + testId + " is not registered in metadata file.",
                registeredIds.contains(testId));
        Assert.assertFalse(
                "TestID " + testId + " appears twice in test suite.",
                processedIds.contains(testId));
        processedIds.add(testId);
    }
}
