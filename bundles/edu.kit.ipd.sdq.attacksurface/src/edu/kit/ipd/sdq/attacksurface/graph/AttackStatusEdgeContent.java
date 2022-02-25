package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class AttackStatusEdgeContent extends AbstractEdgeContent<CredentialSurface, VulnerabilitySurface> {

    public Set<String> getCauseIds() {
        final Set<String> causeIds = new HashSet<>();
        final Iterable<Set<CVSurface>> cIterable = this::getContainedSetCIterator;
        addAllOfIterable(causeIds, cIterable);
        final Iterable<Set<CVSurface>> vIterable = this::getContainedSetVIterator;
        addAllOfIterable(causeIds, vIterable);
        return causeIds;
    }
    
    private void addAllOfIterable(final Set<String> causeIds, final Iterable<Set<CVSurface>> iterable) {
        for (final var causes : iterable) {
            causeIds.addAll(causes.stream().map(CVSurface::getCauseId).collect(Collectors.toSet()));
        }
    }

    public boolean contains(final String causeId) {
        return getCauseIds().contains(causeId);
    }
   
}
