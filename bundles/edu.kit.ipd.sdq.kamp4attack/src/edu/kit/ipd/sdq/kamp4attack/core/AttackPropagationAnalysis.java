package edu.kit.ipd.sdq.kamp4attack.core;

import java.util.ArrayList;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp.propagation.AbstractChangePropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.LinkingPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

/**
 * Entry point for attack propagation
 *
 * @author majuwa
 *
 */

@Component
public class AttackPropagationAnalysis implements AbstractChangePropagationAnalysis<BlackboardWrapper> {

    private CredentialChange changePropagationDueToCredential;

    @Override
    public void runChangePropagationAnalysis(final BlackboardWrapper board) {

        // Setup
        this.changePropagationDueToCredential = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        CachePDP.instance().clearCache();
        CacheCompromised.instance().reset();
        CacheVulnerability.instance().reset();
        CacheCompromised.instance().register(this.changePropagationDueToCredential);
        // prepare

        createInitialStructure(board);

        // Calculate
        do {
            this.changePropagationDueToCredential.setChanged(false);
            calculateAndMarkLinkingPropagation(board);
            calculateAndMarkResourcePropagation(board);
            calculateAndMarkAssemblyPropagation(board);

        } while (this.changePropagationDueToCredential.isChanged());

        // Clear caches
        CachePDP.instance().clearCache();
        CacheCompromised.instance().reset();
        CacheVulnerability.instance().reset();


    }

    private void calculateAndMarkAssemblyPropagation(final BlackboardWrapper board) {
        final var list = new ArrayList<AssemblyContextPropagation>();
        list.add(new AssemblyContextPropagationContext(board, this.changePropagationDueToCredential));
        list.add(new AssemblyContextPropagationVulnerability(board, this.changePropagationDueToCredential));
        for (final var analysis : list) {
            analysis.calculateAssemblyContextToContextPropagation();
            analysis.calculateAssemblyContextToAssemblyContextPropagation();
            analysis.calculateAssemblyContextToGlobalAssemblyContextPropagation();
            analysis.calculateAssemblyContextToLinkingResourcePropagation();
            analysis.calculateAssemblyContextToLocalResourcePropagation();
            analysis.calculateAssemblyContextToRemoteResourcePropagation();
        }
    }

    private void calculateAndMarkResourcePropagation(final BlackboardWrapper board) {
        final var list = new ArrayList<ResourceContainerPropagation>();
        list.add(new ResourceContainerPropagationContext(board, this.changePropagationDueToCredential));
        list.add(new ResourceContainerPropagationVulnerability(board, this.changePropagationDueToCredential));
        for (final var analysis : list) {
            analysis.calculateResourceContainerToContextPropagation();
            analysis.calculateResourceContainerToLinkingResourcePropagation();
            analysis.calculateResourceContainerToLocalAssemblyContextPropagation();
            analysis.calculateResourceContainerToRemoteAssemblyContextPropagation();
            analysis.calculateResourceContainerToResourcePropagation();
        }
    }

    private void calculateAndMarkLinkingPropagation(final BlackboardWrapper board) {
        final var list = new ArrayList<LinkingPropagation>();
        list.add(new LinkingPropagationContext(board, this.changePropagationDueToCredential));
        list.add(new LinkingPropagationVulnerability(board, this.changePropagationDueToCredential));
        for (final var analysis : list) {
            analysis.calculateLinkingResourceToContextPropagation();
            analysis.calculateLinkingResourceToAssemblyContextPropagation();
            analysis.calculateLinkingResourceToResourcePropagation();
        }
    }

    /**
     * Creates the initial propagation steps from the seed modification
     *
     * @param board
     */
    private void createInitialStructure(final BlackboardWrapper board) {
        final var repository = board.getModificationMarkRepository();
        final var seedModification = repository.getSeedModifications();
        final var attackers = seedModification.getAttackcomponent();
        if (attackers == null) {
            throw new IllegalStateException("No seed modification found");
        }

        repository.getChangePropagationSteps().clear();

        for (final var attacker : attackers) {
            final var localAttacker = attacker.getAffectedElement();

            final var listCredentialChanges = localAttacker.getCredentials().stream().map(context -> {
                final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
                change.setAffectedElement(context);
                return change;
            }).collect(Collectors.toList());

            this.changePropagationDueToCredential.getContextchange().addAll(listCredentialChanges);

            // convert affectedResources to changes
            final var affectedRessourcesList = localAttacker.getCompromisedResources().stream().map(resource -> {
                final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                change.setAffectedElement(resource);
                return change;
            }).collect(Collectors.toList());
            this.changePropagationDueToCredential.getCompromisedresource().addAll(affectedRessourcesList);

            // convert affectedAssemblyContexts to changes
            var assemblyHandler = new AssemblyContextHandler(board,
                    new DataHandlerAttacker(this.changePropagationDueToCredential)) {
                @Override
                protected Optional<CompromisedAssembly> attackComponent(AssemblyContext component, CredentialChange change,
                        EObject source){
                    final var compromisedComponent = KAMP4attackModificationmarksFactory.eINSTANCE
                            .createCompromisedAssembly();
                    compromisedComponent.setAffectedElement(component);
                    return Optional.of(compromisedComponent);
                }
            };

            assemblyHandler.attackAssemblyContext(localAttacker.getCompromisedComponents(),
                    this.changePropagationDueToCredential, null);




            // convert affectedLinkingResources to changes
            final var affectedLinkingList = localAttacker.getCompromisedLinkingResources().stream()
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

}
