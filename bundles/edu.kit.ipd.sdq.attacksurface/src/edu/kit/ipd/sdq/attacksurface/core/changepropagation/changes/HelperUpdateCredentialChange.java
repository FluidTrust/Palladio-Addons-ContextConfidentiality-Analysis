package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.graph.EndpointPair;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;

/**
 * Helper class for updating the credentials of the attacker during the propagation.
 *
 * @author majuwa
 * @author ugnwq
 */
public class HelperUpdateCredentialChange {

    private HelperUpdateCredentialChange() {
        // intentional
    }

    /**
     * Updates the list of stolen credentials based on the stream of newly compromised credentials.
     * The newly compromised streams is filtered with already compromised credentials, that no
     * duplicates can exist
     *
     * @param changes
     *            compromised elements
     * @param streamContextChange
     *            newly compromised credentials
     * @param attackerNodeInGraphArg
     *            the attacker node in the graph
     * @param attackedNodeInGraphArg
     *            node in graph which lead to the credential update
     */
    public static void updateCredentials(final CredentialChange changes,
            final Stream<ContextChange> streamContextChange,
            final AttackStatusNodeContent attackerNodeInGraph,
            final AttackStatusNodeContent attackedNodeInGraph,
            final AttackGraph attackGraph) {
        
        final var endpoints = EndpointPair.ordered(attackedNodeInGraph,
                attackerNodeInGraph);
        final var debugList = streamContextChange.collect(Collectors.toList()); //TODO me use stream directly
        final var edge = new AttackStatusEdge(attackGraph.getEdge(endpoints), endpoints);
        final var listChanges = debugList.stream()
                .filter(e -> attackGraph.getCredentials(edge, false).stream()
                        .noneMatch(f -> 
                            e.getAffectedElement().getId().equals(f.getCauseId())
                                ))
                .collect(Collectors.toList()); 
        
        if (!listChanges.isEmpty()) {
            final var vulnerabilities = findCauseVulnerabilities(listChanges);
            attackGraph.attackNodeWithVulnerabilities(attackerNodeInGraph, attackedNodeInGraph, vulnerabilities);
            attackedNodeInGraph.attack(attackerNodeInGraph);
            changes.setChanged(true);
        }
    }
    
    private static Set<Vulnerability> findCauseVulnerabilities(
            final List<ContextChange> listChanges) {
        return getCausingEntityStream(listChanges)
                    .filter(Vulnerability.class::isInstance)
                    .map(Vulnerability.class::cast)
                    .collect(Collectors.toSet());
    }
    
    private static Stream<Entity> getCausingEntityStream(final List<ContextChange> listChanges) {
        return listChanges
                .stream()
                .map(ModifyEntity::getCausingElements)
                .flatMap(List::stream)
                .filter(Entity.class::isInstance)
                .map(Entity.class::cast);
    }

    /**
     * Creates a new {@link ContextChange} object. 
     * It is used for storing compromised credentials and the causes for the compromisation.
     *
     * @param usageSpecification
     *            compromised credential
     * @param sources
     *            collection of objects from whom the credential was stolen
     * @return new {@link ContextChange}
     */
    public static ContextChange createContextChange(final UsageSpecification usageSpecification,
            final Collection<? extends EObject> sources) {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        change.setToolderived(true);
        change.setAffectedElement(usageSpecification);
        if (sources != null && !sources.isEmpty()) {
            change.getCausingElements().addAll(sources);
        }
        return change;
    }

}
