package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Represents an abstract class for implementing the base features of an {@link EdgeContent}.
 * 
 * @author ugnwq
 * @version 1.0
 *
 * @param <C> - the C {@link CredentialsVulnearbilitiesSurface} type
 * @param <V> - the V {@link CredentialsVulnearbilitiesSurface} type
 */
public abstract class AbstractEdgeContent<C extends CredentialsVulnearbilitiesSurface, V extends CredentialsVulnearbilitiesSurface> implements EdgeContent<C, V> {
    private final Set<Set<? extends CredentialsVulnearbilitiesSurface>> setCSets;
    private final Set<Set<? extends CredentialsVulnearbilitiesSurface>> setVSets;
    
    protected AbstractEdgeContent() {
        this.setCSets = new HashSet<>();
        this.setVSets = new HashSet<>();
    }

    @Override
    public Iterator<Set<? extends CredentialsVulnearbilitiesSurface>> getContainedSetCIterator() {
        return this.setCSets.iterator();
    }

    @Override
    public Iterator<Set<? extends CredentialsVulnearbilitiesSurface>> getContainedSetVIterator() {
        return this.setVSets.iterator();
    }

    @Override
    public boolean addSet(final Set<? extends CredentialsVulnearbilitiesSurface> toAdd) {
        final var cSet = toAdd
                .stream()
                .filter(CredentialsVulnearbilitiesSurface::isCredential)
                .collect(Collectors.toSet());
        boolean ret = false;
        if (!cSet.isEmpty()) {
            addSetC(cSet);
            ret = true;
        }
        final var vSet = toAdd
                .stream()
                .filter(v -> !v.isCredential())
                .collect(Collectors.toSet());
        if (!vSet.isEmpty()) {
            addSetV(vSet);
            ret = true;
        }
        return ret;
    }
    
    @Override
    public boolean addSetC(final Set<? extends CredentialsVulnearbilitiesSurface> toAdd) {
        return this.setCSets.add(toAdd);
    }

    @Override
    public boolean addSetV(Set<? extends CredentialsVulnearbilitiesSurface> toAdd) {
        return this.setVSets.add(toAdd);
    }

    @Override
    public int getCCollectionSize() {
        return this.setCSets.size();
    }

    @Override
    public int getVCollectionSize() {
        return this.setVSets.size();
    }

    @Override
    public int hashCode() {
        return Objects.hash(setCSets, setVSets);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AbstractEdgeContent<?, ?> other = (AbstractEdgeContent<?, ?>) obj;
        return Objects.equals(setCSets, other.setCSets) && Objects.equals(setVSets, other.setVSets);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [setCSets=" + setCSets + ", setVSets=" + setVSets + "]";
    }
}
