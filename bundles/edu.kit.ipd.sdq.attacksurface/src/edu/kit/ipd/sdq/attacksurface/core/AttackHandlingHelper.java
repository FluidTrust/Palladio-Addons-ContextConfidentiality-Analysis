package edu.kit.ipd.sdq.attacksurface.core;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.SurfaceAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.CredentialSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialSurface;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

/**
 * Helper class for attack handling. 
 * 
 * @author ugnwq
 * @version 1.0
 */
public final class AttackHandlingHelper {
    private AttackHandlingHelper() {
        assert false;
    }

    /**
     * 
     * @param modelStorage - the model storage
     * @param path - the path
     * @param isEarly - whether this call is an early filtering
     * @return whether the last element in the given path is filtered
     */
    public static boolean isFiltered(final BlackboardWrapper modelStorage, final AttackPath path,
            final boolean isEarly) {
        final var surfaceAttacker = getSurfaceAttacker(modelStorage);
        final var filterCriteria = surfaceAttacker.getFiltercriteria();
        final var systemIntegrations = path.getPath();
        for (final var filterCriterion : filterCriteria) {
            if ( (!isEarly || filterCriterion.isFilteringEarly())
                    && systemIntegrations
                        .stream()
                        .anyMatch(s ->
                            filterCriterion.isElementFiltered(s, surfaceAttacker, path))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 
     * @param modelStorage - the model storage
     * @return the surface attacker
     */
    public static SurfaceAttacker getSurfaceAttacker(final BlackboardWrapper modelStorage) {
        if (modelStorage.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().isEmpty()) {
            throw new IllegalStateException("No attacker selected");
        }
        if (modelStorage.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().size() > 2) {
            throw new IllegalStateException("More than one attacker");
        }
        return modelStorage.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().get(0)
                .getAffectedElement();
    }
    
    /**
     * 
     * @param modelStorage - the model storage
     * @return all attacks
     */
    public static List<Attack> getAttacks(final BlackboardWrapper modelStorage) {
        final var listAttackers = Arrays.asList(getSurfaceAttacker(modelStorage))
                .stream()
                .map(SurfaceAttacker::getAttacker)
                .collect(Collectors.toList());
        return listAttackers.stream().flatMap(a -> a.getAttacks().stream())
                .collect(Collectors.toList());
    }

    /**
     * Attacks the given node with initial credentials (also found in this method) if it is necessary.
     * 
     * @param modelStorage - the model storage
     * @param attackGraph - the attack graph
     * @param nodeContent - the node content (finding takes place in this method)
     * @return whether compromisation was done
     */
    public static boolean attackNodeContentWithInitialCredentialIfNecessary(final BlackboardWrapper modelStorage,
            final AttackGraph attackGraph, final AttackStatusNodeContent nodeContent) {
        final var node = attackGraph.findNode(nodeContent);
        final Set<CredentialSurface> credentialCauses = getCredentialIntegrationCauses(modelStorage, node);
        final Set<CredentialSurface> necessaryCauses = getNecessaryCauses(credentialCauses, attackGraph, node);
        if (!node.isCompromised() && !necessaryCauses.isEmpty()) {
            final var selectedBefore = attackGraph.getSelectedNode();
            attackGraph.setSelectedNode(node);
            attackGraph.compromiseSelectedNode(necessaryCauses, node);
            node.addInitiallyNecessaryCredentials(necessaryCauses);
            attackGraph.setSelectedNode(selectedBefore);
            return true;
        }
        return false;
    }

    private static Set<CredentialSurface> getNecessaryCauses(Set<CredentialSurface> credentialCauses, AttackGraph attackGraph,
            AttackStatusNodeContent node) {
        return credentialCauses
                .stream()
                .filter(c -> attackGraph.getCompromisationCauseIds(node)
                        .stream()
                        .noneMatch(identifier -> identifier.getId().equals(c.getCauseId())))
                .collect(Collectors.toSet());
    }

    private static Set<CredentialSurface> getCredentialIntegrationCauses(BlackboardWrapper modelStorage,
            AttackStatusNodeContent node) {
        return modelStorage.getVulnerabilitySpecification()
                .getVulnerabilities()
                .stream()
                .filter(CredentialSystemIntegration.class::isInstance)
                .filter(s -> 
                    PCMElementType.typeOf(s.getPcmelement()).getElementEqualityPredicate(node.getContainedElement()).test(s))
                .map(SystemIntegration::getIdOfContent)
                .map(CredentialSurface::new)
                .collect(Collectors.toSet());
    }
}
