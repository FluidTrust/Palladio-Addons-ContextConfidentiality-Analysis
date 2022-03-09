package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Represents an edge content for the attack status containing the cause IDs for credentials and vulnerabilites.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackStatusEdgeContent extends AbstractEdgeContent<CredentialSurface, VulnerabilitySurface> {

    /**
     * 
     * @return the cause IDs
     */
    public Set<String> getCauseIds() {
        final Set<String> causeIds = new HashSet<>();
        causeIds.addAll(getCredentialCauseIds());
        causeIds.addAll(getVulnerabilityCauseIds());
        return causeIds;
    }
    
    /**
     * 
     * @return the credential cause IDs
     */
    public Set<String> getCredentialCauseIds() {
        final Set<String> causeIds = new HashSet<>();
        final Iterable<Set<CVSurface>> cIterable = this::getContainedSetCIterator;
        addAllOfIterable(causeIds, cIterable);
        return causeIds;
    }

    /**
     * 
     * @return the vulnerability cause IDs
     */
    public Set<String> getVulnerabilityCauseIds() {
        final Set<String> causeIds = new HashSet<>();
        final Iterable<Set<CVSurface>> vIterable = this::getContainedSetVIterator;
        addAllOfIterable(causeIds, vIterable);
        return causeIds;
    }
    
    private void addAllOfIterable(final Set<String> causeIds, final Iterable<Set<CVSurface>> iterable) {
        for (final var causes : iterable) {
            causeIds.addAll(causes.stream().map(CVSurface::getCauseId).collect(Collectors.toSet()));
        }
    }

    /**
     * 
     * @param causeId - the cause ID
     * @return whether the cause ID is contained in this edge
     */
    public boolean contains(final String causeId) {
        return getCauseIds().contains(causeId);
    }
   
}
