package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import de.uka.ipd.sdq.identifier.Identifier;

/**
 * Represents an edge content for the attack status containing the cause IDs for credentials and vulnerabilites.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackStatusEdgeContent extends AbstractEdgeContent<CredentialSurface, VulnerabilitySurface> {

    /**
     * 
     * @return the causes identifiers
     */
    public Set<Identifier> getCauses() {
        final Set<Identifier> causeIds = new HashSet<>();
        causeIds.addAll(getCredentialCauseIds());
        causeIds.addAll(getVulnerabilityCauseIds());
        return causeIds;
    }
    
    /**
     * 
     * @return the credential causes
     */
    public Set<Identifier> getCredentialCauseIds() {
        final Set<Identifier> causeIds = new HashSet<>();
        final Iterable<Set<? extends CredentialsVulnearbilitiesSurface>> cIterable = this::getContainedSetCIterator;
        addAllOfIterable(causeIds, cIterable);
        return causeIds;
    }

    /**
     * 
     * @return the vulnerability cause IDs
     */
    public Set<Identifier> getVulnerabilityCauseIds() {
        final Set<Identifier> causeIds = new HashSet<>();
        final Iterable<Set<? extends CredentialsVulnearbilitiesSurface>> vIterable = this::getContainedSetVIterator;
        addAllOfIterable(causeIds, vIterable);
        return causeIds;
    }
    
    private void addAllOfIterable(final Set<Identifier> causes, final Iterable<Set<? extends CredentialsVulnearbilitiesSurface>> iterable) {
        for (final var newCauses : iterable) {
            causes.addAll(newCauses.stream().map(CredentialsVulnearbilitiesSurface::getCause).collect(Collectors.toSet()));
        }
    }

    /**
     * 
     * @param cause - the cause id
     * @return whether the cause is contained in this edge
     */
    public boolean contains(final String causeId) {
        return getCauses().stream().anyMatch(c -> c.getId().equals(causeId));
    }
   
}
