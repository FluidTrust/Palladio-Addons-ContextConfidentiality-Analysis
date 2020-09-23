package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import java.util.Collection;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class LinkingChange extends Change<LinkingResource> {

    public LinkingChange(BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<LinkingResource> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(modelStorage, LinkingResource.class);
    }

    public void calculateLinkingResourceToContextPropagation(CredentialChange changes) {
        var listCompromisedLinkingResources = changes.getCompromisedlinkingresource().stream()
                .map(CompromisedLinkingResource::getAffectedElement).collect(Collectors.toList());
        
        var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream().filter(
                e -> listCompromisedLinkingResources.stream().anyMatch(f -> EcoreUtil.equals(e.getLinkingresource(), f)));
        
        updateFromContextProviderStream(changes, streamAttributeProvider);
        
    }
    


}
