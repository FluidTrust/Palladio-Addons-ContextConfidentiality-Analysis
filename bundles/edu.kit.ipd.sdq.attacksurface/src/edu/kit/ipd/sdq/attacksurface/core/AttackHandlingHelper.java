package edu.kit.ipd.sdq.attacksurface.core;

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
import edu.kit.ipd.sdq.attacksurface.graph.CVSurface;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialSurface;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;

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
     * @param board - the model storage
     * @param path - the path
     * @return whether the last element in the given path is filtered
     */
    public static boolean isFiltered(final BlackboardWrapper board, final AttackPath path) {
        final var surfaceAttacker = getSurfaceAttacker(board);
        final var filterCriteria = surfaceAttacker.getFiltercriteria();
        final var systemIntegration = path.getPath().get(path.getPath().size() - 1);
        for (final var filterCriterion : filterCriteria) {
            if (filterCriterion.isFilteringEarly()
                    && filterCriterion.isElementFiltered(systemIntegration, surfaceAttacker, path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 
     * @param board - the model storage
     * @return the surface attacker
     */
    public static SurfaceAttacker getSurfaceAttacker(final BlackboardWrapper board) {
        if (board.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().isEmpty()) {
            throw new IllegalStateException("No attacker selected");
        }
        if (board.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().size() > 2) {
            throw new IllegalStateException("More than one attacker");
        }
        return board.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().get(0)
                .getAffectedElement();
    }
    
    /**
     * 
     * @param board - the model storage
     * @return all attacks
     */
    public static List<Attack> getAttacks(final BlackboardWrapper board) {
        final var listAttackers = board.getModificationMarkRepository().getSeedModifications()
                .getAttackcomponent();
        return listAttackers.stream().flatMap(e -> e.getAffectedElement().getAttacks().stream())
                .collect(Collectors.toList());
    }

    /**
     * Attacks the given node with initial credentials (also found in this method) if it is necessary.
     * 
     * @param board - the model storage
     * @param attackGraph - the attack graph
     * @param nodeContent - the node content (finding takes place in this method)
     * @return whether compromisation was done
     */
    public static boolean attackNodeContentWithInitialCredentialIfNecessary(final BlackboardWrapper board,
            final AttackGraph attackGraph, final AttackStatusNodeContent nodeContent) {
        final var node = attackGraph.findNode(nodeContent);
        final Set<CVSurface> credentialCauses = getCredentialIntegrationCauses(board, attackGraph, node);
        final Set<CVSurface> necessaryCauses = getNecessaryCauses(credentialCauses, attackGraph, node);
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

    private static Set<CVSurface> getNecessaryCauses(Set<CVSurface> credentialCauses, AttackGraph attackGraph,
            AttackStatusNodeContent node) {
        return credentialCauses
                .stream()
                .filter(c -> !attackGraph.getCompromisationCauseIds(node).contains(c.getCauseId()))
                .collect(Collectors.toSet());
    }

    private static Set<CVSurface> getCredentialIntegrationCauses(BlackboardWrapper board, AttackGraph attackGraph,
            AttackStatusNodeContent node) {
        return board.getVulnerabilitySpecification()
                .getVulnerabilities()
                .stream()
                .filter(CredentialSystemIntegration.class::isInstance)
                .filter(s -> 
                    PCMElementType.typeOf(s.getPcmelement()).getElementIdEqualityPredicate(node.getContainedElement()).test(s))
                .map(SystemIntegration::getIdOfContent)
                .map(CredentialSurface::new)
                .collect(Collectors.toSet());
    }
}
