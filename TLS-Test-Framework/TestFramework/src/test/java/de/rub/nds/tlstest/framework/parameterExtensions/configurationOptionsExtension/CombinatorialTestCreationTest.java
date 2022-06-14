/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.ipog.Ipog;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.engine.report.Reporter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

import java.util.*;
import java.util.function.Supplier;

public class CombinatorialTestCreationTest {
    private static final Logger LOGGER = LogManager.getLogger();

    public class LoggerReporter implements Reporter {
        @Override
        public void report(ReportLevel level, Report report) {
            LOGGER.warn("Generation Reporter ({}): {}", level.toString(), report);
        }

        @Override
        public void report(ReportLevel level, Supplier<Report> reportSupplier) {
            LOGGER.warn("Generation Reporter ({}): {}", level.toString(), reportSupplier.get());
        }
    }

    private TestModel modelOf(int strength, List<Integer> sizeList){
        int[] sizeArray = new int[sizeList.size()];
        for(int i = 0; i < sizeList.size(); i++) sizeArray[i] = sizeList.get(i);
        return new TestModel(strength, sizeArray, new LinkedList<>(), new LinkedList<>());
    }

    private int getCombinationCount(int strength, List<Integer> sizeList){
        TestModel model = modelOf(strength, sizeList);
        Ipog ipog = new Ipog(new HardConstraintCheckerFactory());
        Set<Supplier<TestInputGroup>> suppliers = ipog.generate(model, new LoggerReporter());

        TestInputGroup testInputGroup = null;
        for(Supplier<TestInputGroup> s : suppliers){
            TestInputGroup group = s.get();
            if(group.getIdentifier() == "Positive IpogAlgorithm Tests"){
                testInputGroup = group;
                break;
            }
        }
        if(testInputGroup == null){
            throw new RuntimeException("Configuration option combination could not be created.");
        }

        return testInputGroup.getTestInputs().size();
    }

    //@Test
    // Can be used to estimate the runtime of config options tests
    public void countTestVectorsForSetups(){
        List<Integer> sizesDefaultParameters = Arrays.asList(30,8,7,10,4,2,2,2,2,2,2,2,2,2,2,2,2,2);
        List<Integer> sizesCOParameters = Arrays.asList(5,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2);

        List<Integer> sizesOldCombined = new LinkedList<>(sizesDefaultParameters);
        sizesOldCombined.addAll(sizesCOParameters);

        for(int strength = 1; strength < 4; strength++){
            int defaultSize = getCombinationCount(strength, sizesDefaultParameters);
            int COSize = getCombinationCount(strength, sizesCOParameters);
            int oldSize = getCombinationCount(strength, sizesOldCombined);
            int everyWithEverySize = defaultSize * COSize;

            List<Integer> sizesIpmCeption = new LinkedList<>(sizesDefaultParameters);
            sizesIpmCeption.add(COSize);

            int ipmCeptionSize = getCombinationCount(strength, sizesIpmCeption);

            System.out.println(String.format(
                    "---  Strength %d  -----------------\n"+
                    "Combinations (default):          %d\n"+
                    "Combinations (CO alone):         %d\n"+
                    "Combinations (old combined):     %d\n"+
                    "Combinations (every-with-every): %d\n"+
                    "Combinations (IPM-ception):      %d\n"+
                    "----------------------------------------\n",
                    strength, defaultSize,COSize,oldSize,everyWithEverySize,ipmCeptionSize
            ));
        }




    }
}
