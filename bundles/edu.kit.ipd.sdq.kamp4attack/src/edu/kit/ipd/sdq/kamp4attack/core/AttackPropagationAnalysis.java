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
    public void runChangePropagationAnalysis(BlackboardWrapper board) {
        // Setup
        this.changePropagationDueToCredential = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        // prepare

        createInitialStructure(board);

        // Calculate
        do {
            changePropagationDueToCredential.setChanged(false);
            calculateAndMarkLinkingPropagation(board);
            calculateAndMarkResourcePropagation(board);
            calculateAndMarkToAssemblyPropagation(board);

        } while (changePropagationDueToCredential.isChanged());

    }

    private void calculateAndMarkToAssemblyPropagation(BlackboardWrapper board) {
        var list = new ArrayList<AssemblyContextPropagation>();
        list.add(new AssemblyContextPropagationContext(board));
        list.add(new AssemblyContextPropagationVulnerability(board));
        for(var analysis: list) {
            analysis.calculateAssemblyContextToContextPropagation(changePropagationDueToCredential);
            analysis.calculateAssemblyContextToAssemblyContextPropagation(changePropagationDueToCredential);
            analysis.calculateAssemblyContextToLinkingResourcePropagation(changePropagationDueToCredential);
            analysis.calculateAssemblyContextToLocalResourcePropagation(changePropagationDueToCredential);
            analysis.calculateAssemblyContextToRemoteResourcePropagation(changePropagationDueToCredential);
        }
    }

    private void calculateAndMarkResourcePropagation(BlackboardWrapper board) {
        var list = new ArrayList<ResourceContainerPropagation>();
        list.add(new ResourceContainerPropagationContext(board));
        list.add(new ResourceContainerPropagationVulnerability(board));
        for(var analysis: list) {
            analysis.calculateResourceContainerToContextPropagation(changePropagationDueToCredential);
            analysis.calculateResourceContainerToLinkingResourcePropagation(changePropagationDueToCredential);
            analysis.calculateResourceContainerToLocalAssemblyContextPropagation(changePropagationDueToCredential);
            analysis.calculateResourceContainerToRemoteAssemblyContextPropagation(changePropagationDueToCredential);
            analysis.calculateResourceContainerToResourcePropagation(changePropagationDueToCredential);
        }
    }

    private void calculateAndMarkLinkingPropagation(BlackboardWrapper board) {
        var list = new ArrayList<LinkingPropagation>();
        list.add(new LinkingPropagationContext(board));
        list.add(new LinkingPropagationVulnerability(board));
        for(var analysis: list) {
            analysis.calculateLinkingResourceToContextPropagation(changePropagationDueToCredential);
            analysis.calculateLinkingResourceToAssemblyContextPropagation(changePropagationDueToCredential);
            analysis.calculateLinkingResourceToResourcePropagation(changePropagationDueToCredential);
        }
    }

    /**
     * Creates the initial propagation steps from the seed modification
     * 
     * @param board
     */
    private void createInitialStructure(BlackboardWrapper board) {
        var repository = board.getModificationMarkRepository();
        var seedModification = repository.getSeedModifications();
        var attackers = seedModification.getAttackcomponent();
        if (attackers == null)
            throw new IllegalStateException("No seed modification found");

        repository.getChangePropagationSteps().clear();

        for (var attacker : attackers) {
            var localAttacker = attacker.getAffectedElement();
            
            
            var listCredentialChanges = localAttacker.getCredentials().stream().map(context -> {
                var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
                change.setAffectedElement(context);
                return change;
            }).collect(Collectors.toList());
            
            changePropagationDueToCredential.getContextchange().addAll(listCredentialChanges);

            // convert affectedResources to changes
            var affectedRessourcesList = localAttacker.getCompromisedResources().stream().map(resource -> {
                var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                change.setAffectedElement(resource);
                return change;
            }).collect(Collectors.toList());
            changePropagationDueToCredential.getCompromisedresource().addAll(affectedRessourcesList);

            // convert affectedAssemblyContexts to changes
            var affectedComponentsList = localAttacker.getCompromisedComponents().stream().map(assemblyComponent -> {
                var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
                change.setAffectedElement(assemblyComponent);
                return change;
            }).collect(Collectors.toList());
            changePropagationDueToCredential.getCompromisedassembly().addAll(affectedComponentsList);

            // convert affectedLinkingResources to changes
            var affectedLinkingList = localAttacker.getCompromisedLinkingResources().stream().map(linkingResource -> {
                var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedLinkingResource();
                change.setAffectedElement(linkingResource);
                return change;
            }).collect(Collectors.toList());
            changePropagationDueToCredential.getCompromisedlinkingresource().addAll(affectedLinkingList);

        }
        board.getModificationMarkRepository().getChangePropagationSteps().add(changePropagationDueToCredential);
    }

}
