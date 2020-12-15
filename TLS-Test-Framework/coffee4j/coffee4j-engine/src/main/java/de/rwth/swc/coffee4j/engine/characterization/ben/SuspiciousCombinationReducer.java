package de.rwth.swc.coffee4j.engine.characterization.ben;

import de.rwth.swc.coffee4j.engine.util.Combinator;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.stream.Collectors;

import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.NO_VALUE;
import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.contains;
import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.numberOfSetParameters;
import static de.rwth.swc.coffee4j.engine.util.IntArrayWrapper.wrap;

final class SuspiciousCombinationReducer {
    
    private SuspiciousCombinationReducer() {
    }
    
    static Set<IntArrayWrapper> reduce(int[] parameterSizes, Collection<IntArrayWrapper> suspiciousCombinations) {
        Preconditions.notNull(parameterSizes);
        Preconditions.notNull(suspiciousCombinations);
        Preconditions.check(parameterSizes.length > 0);
        final int sizeOfCombinations = getSizeOfAllCombinations(suspiciousCombinations);
        
        if (suspiciousCombinations.isEmpty()) {
            return Collections.emptySet();
        } else {
            final Set<Bucket> buckets = createBuckets(parameterSizes, sizeOfCombinations - 1);
            fillBuckets(buckets, suspiciousCombinations);
            return getReducedSuspiciousCombinations(buckets, parameterSizes);
        }
    }
    
    private static int getSizeOfAllCombinations(Collection<IntArrayWrapper> combinations) {
        if (!combinations.isEmpty()) {
            final Iterator<IntArrayWrapper> iterator = combinations.iterator();
            final int firstSize = numberOfSetParameters(iterator.next().getArray());
            while (iterator.hasNext()) {
                Preconditions.check(firstSize == numberOfSetParameters(iterator.next().getArray()));
            }
            return firstSize;
        }
        return 0;
    }
    
    private static Set<Bucket> createBuckets(int[] parameters, int size) {
        return Combinator.computeCombinations(parameters, size).stream().map(Bucket::new).collect(Collectors.toSet());
    }
    
    private static void fillBuckets(Set<Bucket> buckets, Collection<IntArrayWrapper> suspiciousCombinations) {
        for (IntArrayWrapper suspiciousCombination : suspiciousCombinations) {
            for (Bucket bucket : buckets) {
                bucket.addIfContains(suspiciousCombination);
            }
        }
    }
    
    private static Set<IntArrayWrapper> getReducedSuspiciousCombinations(Set<Bucket> buckets, int[] parameterSizes) {
        final Set<IntArrayWrapper> reducedSuspiciousCombinations = new HashSet<>();
        for (Bucket bucket : buckets) {
            if (bucket.containsAllPossibleContainingCombinations(parameterSizes)) {
                reducedSuspiciousCombinations.add(wrap(bucket.getCombination()));
            }
        }
        
        return reducedSuspiciousCombinations;
    }
    
    private static class Bucket {
        
        private final int[] combination;
        
        private final Set<IntArrayWrapper> containingCombinations = new HashSet<>();
        
        private Bucket(int[] combination) {
            Preconditions.notNull(combination);
            
            this.combination = combination;
        }
        
        private void addIfContains(IntArrayWrapper possibleContainingCombination) {
            Preconditions.notNull(possibleContainingCombination);
            
            if (contains(possibleContainingCombination.getArray(), combination)) {
                containingCombinations.add(possibleContainingCombination);
            }
        }
        
        private boolean containsAllPossibleContainingCombinations(int[] parameterSizes) {
            Preconditions.notNull(parameterSizes);
            Preconditions.check(parameterSizes.length >= combination.length);
            
            int numberOfPossibleContainingCombinations = 0;
            for (int parameter = 0; parameter < parameterSizes.length; parameter++) {
                if (combination[parameter] == NO_VALUE) {
                    numberOfPossibleContainingCombinations += parameterSizes[parameter];
                }
            }
            return numberOfPossibleContainingCombinations == containingCombinations.size();
        }
        
        private int[] getCombination() {
            return combination;
        }
        
    }
    
}
