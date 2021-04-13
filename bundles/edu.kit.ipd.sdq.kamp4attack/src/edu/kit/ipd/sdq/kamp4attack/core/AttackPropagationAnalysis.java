package edu.kit.ipd.sdq.kamp4attack.core;

import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;

import edu.kit.ipd.sdq.kamp.propagation.AbstractChangePropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.AssemblyChange;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.ContextChanges;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.LinkingChange;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.ResourceChange;
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
            calculateAndMarkToContextPropagation(board);

        } while (changePropagationDueToCredential.isChanged());

    }

    private void calculateAndMarkToContextPropagation(BlackboardWrapper board) {
        var change = new ContextChanges(board);
        change.calculateContextToResourcePropagation(changePropagationDueToCredential);
        change.calculateContextToAssemblyPropagation(changePropagationDueToCredential);
        change.calculateContextLinkingToResourcePropagation(changePropagationDueToCredential);
        change.calculateContextToLinkingPropagation(changePropagationDueToCredential);
    }

    private void calculateAndMarkToAssemblyPropagation(BlackboardWrapper board) {
        var change = new AssemblyChange(board);
        change.calculateAssemblyToContextPropagation(changePropagationDueToCredential);
        change.calculateAssemblyToResourcePropagation(changePropagationDueToCredential);
    }

    private void calculateAndMarkResourcePropagation(BlackboardWrapper board) {
        var change = new ResourceChange(board);
        change.calculateResourceToAssemblyPropagation(changePropagationDueToCredential);
        change.calculateResourceToContextPropagation(changePropagationDueToCredential);
    }

    private void calculateAndMarkLinkingPropagation(BlackboardWrapper board) {
        var change = new LinkingChange(board);
        change.calculateLinkingResourceToContextPropagation(changePropagationDueToCredential);
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
