package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.Iterator;
import java.util.Set;

/**
 * Represents an abstract edge content with two lists of sets, respectively for C and V elements.
 * 
 * @author ugnwq
 * @version 1.0
 * @param <C> the C type
 * @param <V> the V type
 */
public interface EdgeContent<C extends CredentialsVulnearbilitiesSurface, V extends CredentialsVulnearbilitiesSurface> {
    /**
     * iterator over the C set
     * 
     * @return iterator over the C set
     */
    Iterator<Set<? extends CredentialsVulnearbilitiesSurface>> getContainedSetCIterator();
    
    /**
     * iterator over the V set
     * 
     * @return iterator over the V set
     */
    Iterator<Set<? extends CredentialsVulnearbilitiesSurface>> getContainedSetVIterator();
    
    /**
     * Splits the set in C and V and adds them as new sets. An empty set is not added.
     * 
     * @param toAdd - the set to be added
     * @return if the a set was added
     */
    boolean addSet(final Set<? extends CredentialsVulnearbilitiesSurface> toAdd);
    
    /**
     * 
     * @param toAdd - the set of C to be added
     * @return if the set was added
     */
    boolean addSetC(final Set<? extends CredentialsVulnearbilitiesSurface> toAdd);
    
    /**
     * 
     * @param toAdd - the set of V to be added
     * @return if the set was added
     */
    boolean addSetV(final Set<? extends CredentialsVulnearbilitiesSurface> toAdd);
    
    /**
     * 
     * @return the size of the C collection
     */
    int getCCollectionSize();
    
    /**
     * 
     * @return the size of the V collection
     */
    int getVCollectionSize();
    
    @Override
    int hashCode();
    
    @Override
    boolean equals(Object other);

    public static Iterable<Set<CredentialsVulnearbilitiesSurface>> toIterable(final Iterator<Set<CredentialsVulnearbilitiesSurface>> iterator) {
        return () -> iterator;
    }
}
