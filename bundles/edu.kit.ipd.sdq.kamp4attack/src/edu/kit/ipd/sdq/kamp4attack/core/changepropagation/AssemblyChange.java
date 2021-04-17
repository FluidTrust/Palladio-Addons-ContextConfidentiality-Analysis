package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackSpecificationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class AssemblyChange extends Change<AssemblyContext> {

    public AssemblyChange(BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<AssemblyContext> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(modelStorage, AssemblyContext.class);
    }

    public void calculateAssemblyToContextPropagation(CredentialChange changes) {
        var listCompromisedAssemblyContexts = changes.getCompromisedassembly().stream()
                .map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());

        var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
                .filter(e -> listCompromisedAssemblyContexts.stream()
                        .anyMatch(f -> EcoreUtil.equals(e.getAssemblycontext(), f)));

        updateFromContextProviderStream(changes, streamAttributeProvider);
    }

    public void calculateAssemblyToResourcePropagation(CredentialChange changes) {
        
        var listCompromisedContexts = changes.getCompromisedassembly().stream()
                .map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());

        var streamTargetAllocations = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                .filter(e -> listCompromisedContexts.stream()
                        .anyMatch(f -> EcoreUtil.equals(f, e.getAssemblyContext_AllocationContext())));

        var attackableResourceContainers = streamTargetAllocations
                .map(AllocationContext::getResourceContainer_AllocationContext).collect(Collectors.toList());

        var credentials = getCredentials(changes);

        var setAttackedResources = new HashSet<ResourceContainer>();

        attackResourceCredentials(attackableResourceContainers, credentials, setAttackedResources);

//        attackableResourceContainers

//        AttackVector.LOCAL;
        for (var resource : attackableResourceContainers) {
            var vulnerabilityList = this.modelStorage.getVulnerabilitySpecification().getVulnerabilities().stream()
                    .filter(e -> EcoreUtil.equals(e.getResourcecontainer(), resource)).map(systemIntegration -> systemIntegration.getVulnerability()).collect(Collectors.toList());
            var listAttacks = getAttacks();
            var listCredentialsNeeded = getCredentials(resource);
            //TODO: refactor without label
            stop:
            for (var credentialsNeeded: listCredentialsNeeded) {
                for(var vulnerability: vulnerabilityList) {
                    for(var attack : listAttacks) {
                        if(attack.canExploit(vulnerability, credentials, credentialsNeeded, AttackVector.LOCAL)) {
                            setAttackedResources.add(resource);
                            break stop;
                        }
                    }
                }
            }
        }

        for (var container : setAttackedResources) {
            if (changes.getCompromisedresource().stream()
                    .noneMatch(e -> EcoreUtil.equals(e.getAffectedElement(), container))) {
                var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                change.setAffectedElement(container);
                change.setToolderived(true);
                changes.getCompromisedresource().add(change);
                changes.setChanged(true);
            }
        }

    }

    private void attackResourceCredentials(List<ResourceContainer> attackableResourceContainers, ContextSet credentials,
            HashSet<ResourceContainer> setAttacked) {
        for (var container : attackableResourceContainers) {
            var listContextSets = getCredentials(container);
            if (listContextSets.stream().anyMatch(e -> e.checkAccessRight(credentials))) {
                setAttacked.add(container);
            }
        }
    }

    private List<ContextSet> getCredentials(ResourceContainer container) {
        var listContextSets = this.getPolicyStream()
                .filter(e -> EcoreUtil.equals(e.getResourcecontainer(), container))
                .flatMap(e -> e.getPolicy().stream()).collect(Collectors.toList());
        return listContextSets;
    }

}
