package edu.kit.ipd.sdq.attacksurface.core;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.InitialCredentialFilterCriterion;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.StartElementFilterCriterion;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.SurfaceAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.VulnerabilityFilterCriterion;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.ResourceEnvironmentElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemComponent;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.attacksurface.graph.ArchitectureNode;
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

    public static List<UsageSpecification> filteredCredentials(final BlackboardWrapper modelStorage) {
        final var surfaceAttacker = getSurfaceAttacker(modelStorage);
        final var filterCriteria = surfaceAttacker.getFiltercriteria();
        return filterCriteria.parallelStream().filter(InitialCredentialFilterCriterion.class::isInstance)
                .map(InitialCredentialFilterCriterion.class::cast)
                .flatMap(e -> e.getProhibitedInitialCredentials().stream()).toList();
    }

    public static boolean notFilteredVulnerability(final BlackboardWrapper modelStorage,
            final Vulnerability vulnerability) {
        var surfaceAttacker = getSurfaceAttacker(modelStorage);
        return surfaceAttacker.getFiltercriteria().stream().filter(VulnerabilityFilterCriterion.class::isInstance)
                .map(VulnerabilityFilterCriterion.class::cast).allMatch(e -> e.isVulnerabilityInRange(vulnerability));
    }

    public static Set<ArchitectureNode> getStartNodes(BlackboardWrapper modelStorage) {
        var surfaceAttacker = getSurfaceAttacker(modelStorage);
        var listNodes = surfaceAttacker.getFiltercriteria().stream()
                .filter(StartElementFilterCriterion.class::isInstance).map(StartElementFilterCriterion.class::cast)
                .distinct().flatMap(AttackHandlingHelper::getNodeStream).toList();
        return new HashSet<>(listNodes);
    }

    private static Stream<ArchitectureNode> getNodeStream(StartElementFilterCriterion filter) {
        var streamResources = filter.getStartResources().stream().map(AttackHandlingHelper::getResource).map(ArchitectureNode::new);
        var streamComponents = filter.getStartComponents().stream().map(AttackHandlingHelper::getComponent)
                .map(ArchitectureNode::new);

        return Stream.concat(streamComponents, streamResources);

    }

    private static Entity getComponent(SystemComponent component) {
        return component.getAssemblycontext().get(0); // TODO: composite components
    }

    private static Entity getResource(ResourceEnvironmentElement element) {
        if (element.getResourcecontainer() != null) {
            return element.getResourcecontainer();
        } else {
            return element.getLinkingresource();
        }
    }

    /**
     *
     * @param modelStorage
     *            - the model storage
     * @return the surface attacker
     */
    public static SurfaceAttacker getSurfaceAttacker(final BlackboardWrapper modelStorage) {
        if (modelStorage.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().isEmpty()) {
            throw new IllegalStateException("No attacker selected");
        }
        if (modelStorage.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent()
                .size() > 2) {
            throw new IllegalStateException("More than one attacker");
        }
        return modelStorage.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().get(0)
                .getAffectedElement();
    }
}
