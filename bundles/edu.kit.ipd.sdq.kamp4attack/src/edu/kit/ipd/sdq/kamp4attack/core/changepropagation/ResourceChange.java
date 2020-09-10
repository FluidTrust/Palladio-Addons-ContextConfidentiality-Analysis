package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AttributeProvider;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class ResourceChange extends Change<ResourceContainer> {

    public ResourceChange(BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<ResourceContainer> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(modelStorage, ResourceContainer.class);
    }

    public void calculateResourceToContextPropagation(CredentialChange changes) {
        var listInfectedContainer = changes.getCompromisedresource().stream()
                .map(CompromisedResource::getAffectedElement).collect(Collectors.toList());
        
        var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream().filter(
                e -> listInfectedContainer.stream().anyMatch(f -> EcoreUtil.equals(e.getResourcecontainer(), f)));
        
        updateFromContextProviderStream(changes, streamAttributeProvider);
        
        
        
    }

    
    public void calculateResourceToAssemblyPropagation(CredentialChange changes) {
        var listInfectedContainer = changes.getCompromisedresource().stream()
                .map(CompromisedResource::getAffectedElement).collect(Collectors.toList());

        var streamTargetAllocations = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                .filter(e -> listInfectedContainer.stream().anyMatch(f -> EcoreUtil.equals(f, e.getResourceContainer_AllocationContext())));

        var streamAssembly = streamTargetAllocations.map(AllocationContext::getAssemblyContext_AllocationContext);

        var streamChanges = streamAssembly.map(e -> {
            var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
            change.setToolderived(true);
            change.setAffectedElement(e);
            return change;
        });

        var listChanges = streamChanges.filter(e -> {
            return !changes.getCompromisedassembly().stream()
                    .anyMatch(f -> EcoreUtil.equals(f.getAffectedElement(), e.getAffectedElement()));
        }).collect(Collectors.toList());

        changes.getCompromisedassembly().addAll(listChanges);
        if (listChanges.size() > 0)
            changes.setChanged(true);
    }

}
