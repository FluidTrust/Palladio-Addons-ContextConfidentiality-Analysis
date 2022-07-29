package edu.kit.ipd.sdq.attacksurface.core;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.InitialCredentialFilterCriterion;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.StartElementFilterCriterion;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.SurfaceAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.VulnerabilityFilterCriterion;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.CredentialSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.ResourceEnvironmentElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemComponent;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.attacksurface.graph.ArchitectureNode;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialSurface;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackPath;

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
     * @param modelStorage
     *            - the model storage
     * @param path
     *            - the path
     * @param isEarly
     *            - whether this call is an early filtering
     * @return whether the last element in the given path is filtered
     */
    public static boolean isFiltered(final BlackboardWrapper modelStorage, final AttackPath path,
            final boolean isEarly) {
//        final var surfaceAttacker = getSurfaceAttacker(modelStorage);
//        final var filterCriteria = surfaceAttacker.getFiltercriteria();
//        final var systemIntegrations = path.getAttackpathelement();
//        for (final var filterCriterion : filterCriteria) {
//            if ((!isEarly || filterCriterion.isFilteringEarly()) && systemIntegrations.stream()
//                    .anyMatch(s -> filterCriterion.isElementFiltered(s, surfaceAttacker, path))) {
//                return true;
//            }
//        }
        return false;
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

    /**
     * Attacks the given node with initial credentials (also found in this method) if it is
     * necessary.
     *
     * @param modelStorage
     *            - the model storage
     * @param attackGraph
     *            - the attack graph
     * @param nodeContent
     *            - the node content (finding takes place in this method)
     * @return whether compromisation was done
     */
    public static boolean attackNodeContentWithInitialCredentialIfNecessary(final BlackboardWrapper modelStorage,
            final AttackGraph attackGraph, final ArchitectureNode nodeContent) {
//        final var credentialCauses = getCredentialIntegrationCauses(modelStorage, nodeContent);
//        final Set<CredentialSurface> necessaryCauses = getNecessaryCauses(credentialCauses, attackGraph, node);
//        if (!node.isCompromised() && !necessaryCauses.isEmpty()) {
//            final var selectedBefore = attackGraph.getSelectedNode();
//            attackGraph.setSelectedNode(node);
//            attackGraph.compromiseSelectedNode(necessaryCauses, node);
//            node.addInitiallyNecessaryCredentials(necessaryCauses);
//            attackGraph.setSelectedNode(selectedBefore);
//            return true;
//        }
        return false;
    }

//    private static Set<CredentialSurface> getNecessaryCauses(Set<CredentialSurface> credentialCauses, AttackGraph attackGraph,
//            ArchitectureNode node) {
//        return credentialCauses
//                .stream()
//                .filter(c -> attackGraph.getCompromisationCauseIds(node)
//                        .stream()
//                        .noneMatch(identifier -> identifier.getId().equals(c.getCauseId())))
//                .collect(Collectors.toSet());
//    }

    private static Set<CredentialSurface> getCredentialIntegrationCauses(BlackboardWrapper modelStorage,
            ArchitectureNode node) {
        return modelStorage.getVulnerabilitySpecification().getVulnerabilities().stream()
                .filter(CredentialSystemIntegration.class::isInstance).filter(s -> {
                    var pcmELement = s.getPcmelement();
                    if (!pcmELement.getAssemblycontext().isEmpty()) {
                        return EcoreUtil.equals(pcmELement.getAssemblycontext().get(0), node.getEntity());
                    }
                    if (pcmELement.getMethodspecification() != null) {
                        // TODO fix method resoltuion
                        return pcmELement.getMethodspecification().getId().equals(node.getEntity().getId());
                    }
                    if (pcmELement.getResourcecontainer() != null) {
                        return pcmELement.getResourcecontainer().getId().equals(node.getEntity().getId());
                    }
                    if (pcmELement.getLinkingresource() != null) {
                        return pcmELement.getLinkingresource().getId().equals(node.getEntity().getId());
                    }
                    return false;

                }).map(SystemIntegration::getIdOfContent).map(CredentialSurface::new).collect(Collectors.toSet());
    }
}
