package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.Datahandler;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class ResourceContainerHandler extends AttackHandler {

    public ResourceContainerHandler(BlackboardWrapper modelStorage, DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }

    public void attackResourceContainer(Collection<ResourceContainer> containers, CredentialChange change,
            EObject source) {
        var compromisedResources = containers.stream().map(e -> this.attackResourceContainer(e, change, source))
                .flatMap(Optional::stream).collect(Collectors.toList());
        var newCompromisedResources = filterExsiting(compromisedResources, change);
        if (!newCompromisedResources.isEmpty()) {
            handleDataExtraction(newCompromisedResources);
            change.setChanged(true);
            change.getCompromisedresource().addAll(newCompromisedResources);
        }
    }

    private void handleDataExtraction(Collection<CompromisedResource> resources) {
        var dataList = resources.stream()
                .flatMap(resource -> Datahandler
                        .getData(resource.getAffectedElement(), getModelStorage().getAllocation()).stream())
                .collect(Collectors.toList());
        getDataHandler().addData(dataList);
    }

    protected abstract Optional<CompromisedResource> attackResourceContainer(ResourceContainer container,
            CredentialChange change, EObject source);

    private Collection<CompromisedResource> filterExsiting(Collection<CompromisedResource> containers,
            CredentialChange change) {
        return containers.stream().filter(container -> !contains(container, change)).collect(Collectors.toList());

    }

    private boolean contains(CompromisedResource resource, CredentialChange change) {
        return change.getCompromisedresource().stream().anyMatch(referenceContainer -> EcoreUtil
                .equals(referenceContainer.getAffectedElement(), resource.getAffectedElement()));
    }



}
