package edu.kit.ipd.sdq.attacksurface.core;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.SurfaceAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.CredentialSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.CVSurface;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialSurface;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public final class AttackHandlingHelper {
    private AttackHandlingHelper() {
        assert false;
    }

    public static boolean isFiltered(final BlackboardWrapper board, final AttackGraph attackGraph,
            final AttackPath path) {
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

    public static void attackNodeContentWithInitialCredentialIfNecessary(final BlackboardWrapper board,
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
        }
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
