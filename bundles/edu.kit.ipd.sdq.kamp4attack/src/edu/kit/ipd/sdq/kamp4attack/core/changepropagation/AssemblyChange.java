package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
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

        var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream().filter(
                e -> listCompromisedAssemblyContexts.stream().anyMatch(f -> EcoreUtil.equals(e.getAssemblycontext(), f)));

        updateFromContextProviderStream(changes, streamAttributeProvider);
    }

    public void calculateAssemblyToResourcePropagation(CredentialChange changes) {
        var contexts = changes.getContextchange().stream().map(ContextChange::getAffectedElement)
                .collect(Collectors.toList());

        var listCompromisedContexts = changes.getCompromisedassembly().stream()
                .map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());

        var streamTargetAllocations = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                .filter(e -> listCompromisedContexts.stream()
                        .anyMatch(f -> EcoreUtil.equals(f, e.getAssemblyContext_AllocationContext())));

        var attackableResourceContainers = streamTargetAllocations
                .map(AllocationContext::getResourceContainer_AllocationContext).collect(Collectors.toList());

        var credentials = this.createContextSet(contexts);
        
        var setAttackedResources = new HashSet<ResourceContainer>();
        
        attackResourceCredentials(attackableResourceContainers, credentials, setAttackedResources);
        
//        attackableResourceContainers
        
        
        
        
        for(var container:setAttackedResources) {
            if(changes.getCompromisedresource().stream().noneMatch(e-> EcoreUtil.equals(e.getAffectedElement(),container))) {
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
            var listContextSets = this.getPolicyStream()
                    .filter(e -> EcoreUtil.equals(e.getResourcecontainer(), container))
                    .flatMap(e -> e.getPolicy().stream()).collect(Collectors.toList());
            if(listContextSets.stream().anyMatch(e-> e.checkAccessRight(credentials))) {
                setAttacked.add(container);
            }
        }
    }

}
