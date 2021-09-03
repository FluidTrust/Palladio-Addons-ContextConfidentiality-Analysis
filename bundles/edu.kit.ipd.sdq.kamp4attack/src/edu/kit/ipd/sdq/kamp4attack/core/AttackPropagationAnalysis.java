package edu.kit.ipd.sdq.kamp4attack.core;

import java.util.ArrayList;
import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;

import edu.kit.ipd.sdq.kamp.propagation.AbstractChangePropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.LinkingPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

//TODO This is probably the interesting component.

@Component
public class AttackPropagationAnalysis implements AbstractChangePropagationAnalysis<BlackboardWrapper> {

    private CredentialChange changePropagationDueToCredential;

    @Override
    public void runChangePropagationAnalysis(final BlackboardWrapper board) {

        // Setup
        this.changePropagationDueToCredential = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        // prepare

        this.createInitialStructure(board);

        // Calculate
        do {
            this.changePropagationDueToCredential.setChanged(false);
            this.calculateAndMarkLinkingPropagation(board);
            this.calculateAndMarkResourcePropagation(board);
            this.calculateAndMarkAssemblyPropagation(board);

        } while (this.changePropagationDueToCredential.isChanged());

    }

    private void calculateAndMarkAssemblyPropagation(final BlackboardWrapper board) {
        final var list = new ArrayList<AssemblyContextPropagation>();
        list.add(new AssemblyContextPropagationContext(board));
        list.add(new AssemblyContextPropagationVulnerability(board));
        for (final var analysis : list) {
            analysis.calculateAssemblyContextToContextPropagation(this.changePropagationDueToCredential);
            analysis.calculateAssemblyContextToAssemblyContextPropagation(this.changePropagationDueToCredential);
            analysis.calculateAssemblyContextToLinkingResourcePropagation(this.changePropagationDueToCredential);
            analysis.calculateAssemblyContextToLocalResourcePropagation(this.changePropagationDueToCredential);
            analysis.calculateAssemblyContextToRemoteResourcePropagation(this.changePropagationDueToCredential);
        }
    }

    private void calculateAndMarkResourcePropagation(final BlackboardWrapper board) {
        final var list = new ArrayList<ResourceContainerPropagation>();
        list.add(new ResourceContainerPropagationContext(board));
        list.add(new ResourceContainerPropagationVulnerability(board));
        for (final var analysis : list) {
            analysis.calculateResourceContainerToContextPropagation(this.changePropagationDueToCredential);
            analysis.calculateResourceContainerToLinkingResourcePropagation(this.changePropagationDueToCredential);
            analysis.calculateResourceContainerToLocalAssemblyContextPropagation(this.changePropagationDueToCredential);
            analysis.calculateResourceContainerToRemoteAssemblyContextPropagation(
                    this.changePropagationDueToCredential);
            analysis.calculateResourceContainerToResourcePropagation(this.changePropagationDueToCredential);
        }
    }

    private void calculateAndMarkLinkingPropagation(final BlackboardWrapper board) {
        final var list = new ArrayList<LinkingPropagation>();
        list.add(new LinkingPropagationContext(board));
        list.add(new LinkingPropagationVulnerability(board));
        for (final var analysis : list) {
            analysis.calculateLinkingResourceToContextPropagation(this.changePropagationDueToCredential);
            analysis.calculateLinkingResourceToAssemblyContextPropagation(this.changePropagationDueToCredential);
            analysis.calculateLinkingResourceToResourcePropagation(this.changePropagationDueToCredential);
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
            final var affectedComponentsList = localAttacker.getCompromisedComponents().stream()
                    .map(assemblyComponent -> {
                        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
                        change.setAffectedElement(assemblyComponent);
                        return change;
                    }).collect(Collectors.toList());
            this.changePropagationDueToCredential.getCompromisedassembly().addAll(affectedComponentsList);

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
