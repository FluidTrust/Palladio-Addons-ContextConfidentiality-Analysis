package edu.kit.ipd.sdq.attacksurface.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.DefaultSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp.propagation.AbstractChangePropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

/**
 * Entry point for attack surface propagation
 *
 * @author majuwa
 * @author ugnwq
 */

@Component
public class AttackSurfaceAnalysis {

    private CredentialChange changePropagationDueToCredential;

    private Entity crtitcalEntity;

    private AttackGraph attackGraph;

    public void runChangePropagationAnalysis(final BlackboardWrapper board) {

        // Setup
        this.changePropagationDueToCredential = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        CachePDP.instance().clearCache();
        // TODO remove: CacheVulnerability.instance().reset();

        // prepare
        createInitialStructure(board);
        this.attackGraph = new AttackGraph(this.crtitcalEntity);

        // TODO adapt
        // Calculate
        do {
            this.changePropagationDueToCredential.setChanged(false);
            this.attackGraph.resetVisitations();

            calculateAndMarkResourcePropagation(board);
            calculateAndMarkAssemblyPropagation(board);

            /* TODO calculateAndMarkLinkingPropagation(board); */
        } while (this.changePropagationDueToCredential.isChanged());

        // create all attack paths
        this.attackGraph.resetVisitations();
        final var allAttackPathsSurface = this.attackGraph.findAllAttackPaths();
        this.changePropagationDueToCredential.getAttackpaths().addAll(toAttackPaths(board, allAttackPathsSurface));

        // Clear caches
        CachePDP.instance().clearCache();
        // TODO remove: CacheVulnerability.instance().reset();
    }

    // TODO move toAttackPaths method to extra AttackPathConverter class
    /**
     * TODO method for testing the {@link AttackPathSurface} to {@link AttackPath}
     * conversion.
     * 
     * @param allAttackPathsSurface - list of {@link AttackPathSurface} instances
     *                              representing all found paths
     * @return list of {@link AttackPath} instances
     */
    public List<AttackPath> toAttackPaths(final List<AttackPathSurface> allAttackPathsSurface,
            final BlackboardWrapper board) {
        return new ArrayList<>(toAttackPaths(board, allAttackPathsSurface));
    }

    private Collection<AttackPath> toAttackPaths(final BlackboardWrapper board,
            final List<AttackPathSurface> allAttackPathsSurface) {
        final List<AttackPath> allPaths = new ArrayList<>();

        for (final var pathSurface : allAttackPathsSurface) {
            final var attackPathPath = pathSurface.toAttackPath(board, this.crtitcalEntity, false);
            if (!attackPathPath.getPath().isEmpty() && !isFiltered(board, attackPathPath)
                    && isLastElementCriticalElement(attackPathPath)) {
                allPaths.add(attackPathPath);
            }
        }

        return allPaths;
    }

    private boolean isLastElementCriticalElement(final AttackPath attackPath) {
        final var path = attackPath.getPath();
        final var lastElement = path.get(path.size() - 1).getPcmelement();
        final var lastEntity = PCMElementType.typeOf(lastElement).getEntity(lastElement);
        return lastEntity.getId().equals(this.crtitcalEntity.getId());
    }

    private boolean isFiltered(final BlackboardWrapper board, final AttackPath path) {
        return FilterCriteriaHandling.isFiltered(board, this.attackGraph, path);
    }

    private void createInitialStructure(BlackboardWrapper board) {
        final var repository = board.getModificationMarkRepository();
        final var seedModification = repository.getSeedModifications();
        final var attackers = seedModification.getSurfaceattackcomponent();
        if (attackers == null) {
            throw new IllegalStateException("No seed modification found");
        }

        repository.getChangePropagationSteps().clear();

        for (final var attacker : attackers) { // TODO at the moment only one attacker allowed
            final var localAttacker = attacker.getAffectedElement();
            final var criticalPCMElement = localAttacker.getCriticalElement();
            this.crtitcalEntity = PCMElementType.typeOf(criticalPCMElement).getEntity(criticalPCMElement);

            final var listCredentialChanges = localAttacker.getAttacker().getCredentials().stream().map(context -> {
                final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
                change.setAffectedElement(context);
                return change;
            }).collect(Collectors.toList());

            this.changePropagationDueToCredential.getContextchange().addAll(listCredentialChanges);

            // convert affectedResources to changes
            final var affectedRessourcesList = localAttacker.getAttacker().getCompromisedResources().stream()
                    .map(resource -> {
                        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                        change.setAffectedElement(resource);
                        return change;
                    }).collect(Collectors.toList());
            this.changePropagationDueToCredential.getCompromisedresource().addAll(affectedRessourcesList);

            // TODO add all possible attacks to the attack container and the attacker

            // convert affectedLinkingResources to changes
            final var affectedLinkingList = localAttacker.getAttacker().getCompromisedLinkingResources().stream()
                    .map(linkingResource -> {
                        final var change = KAMP4attackModificationmarksFactory.eINSTANCE
                                .createCompromisedLinkingResource();
                        change.setAffectedElement(linkingResource);
                        return change;
                    }).collect(Collectors.toList());
            this.changePropagationDueToCredential.getCompromisedlinkingresource().addAll(affectedLinkingList);

        }
        board.getModificationMarkRepository().getChangePropagationSteps().add(this.changePropagationDueToCredential);

    }

    /**
     * Calculates the propagation starting from {@link AssemblyContext}s. The
     * analyses start from the critical element and try to calculate back possible
     * attack paths to it. <br/>
     * TODO: consider credentials and propagation to other model elements except
     * assembly contexts
     * 
     * @param board - the model storage
     */
    private void calculateAndMarkAssemblyPropagation(final BlackboardWrapper board) {
        // TODO complete implementation

        final var list = new ArrayList<AssemblyContextPropagation>();
        list.add(new AssemblyContextPropagationVulnerability(board, this.changePropagationDueToCredential,
                this.attackGraph));
        list.add(new AssemblyContextPropagationContext(board, this.changePropagationDueToCredential, 
                this.attackGraph));
        for (final var analysis : list) {
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToAssemblyContextPropagation);
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToGlobalAssemblyContextPropagation);
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToLocalResourcePropagation);
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToRemoteResourcePropagation);
            //TODO to linking
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToContextPropagation);
        }
    }

    private void callMethodAfterResettingVisitations(final Runnable runnable) {
        this.attackGraph.resetVisitations();
        runnable.run();
    }

    private void calculateAndMarkResourcePropagation(final BlackboardWrapper board) {
        // TODO complete implementation

        final var list = new ArrayList<ResourceContainerPropagation>();
        list.add(new ResourceContainerPropagationVulnerability(board, this.changePropagationDueToCredential,
                this.attackGraph));
        list.add(new ResourceContainerPropagationContext(board,
                this.changePropagationDueToCredential, this.attackGraph));
        for (final var analysis : list) { // TODO adapt
            callMethodAfterResettingVisitations(analysis::calculateResourceContainerToResourcePropagation);
            callMethodAfterResettingVisitations(analysis::calculateResourceContainerToLocalAssemblyContextPropagation);
            callMethodAfterResettingVisitations(analysis::calculateResourceContainerToRemoteAssemblyContextPropagation);
            //TODO to linking
            callMethodAfterResettingVisitations(analysis::calculateResourceContainerToContextPropagation);
        }
    }

}
