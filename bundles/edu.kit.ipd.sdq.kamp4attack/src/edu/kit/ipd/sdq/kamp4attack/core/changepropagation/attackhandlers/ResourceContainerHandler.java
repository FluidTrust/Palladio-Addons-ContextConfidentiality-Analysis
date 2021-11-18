package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class ResourceContainerHandler extends AttackHandler {

    public ResourceContainerHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }

    public void attackResourceContainer(final Collection<ResourceContainer> containers, final CredentialChange change,
            final EObject source) {
        final var compromisedResources = containers.stream().map(e -> this.attackResourceContainer(e, change, source))
                .flatMap(Optional::stream).distinct().collect(Collectors.toList());
        final var newCompromisedResources = filterExsiting(compromisedResources, change);
        if (!newCompromisedResources.isEmpty()) {
            handleDataExtraction(newCompromisedResources);
            change.setChanged(true);
            change.getCompromisedresource().addAll(newCompromisedResources);
        }
    }

    private void handleDataExtraction(final Collection<CompromisedResource> resources) {

        Collection<ResourceContainer> filteredComponents = resources.stream()
                .map(CompromisedResource::getAffectedElement).collect(Collectors.toList());

        filteredComponents = CollectionHelper.removeDuplicates(filteredComponents);

        final var dataList = filteredComponents.stream()
                .flatMap(resource -> DataHandler.getData(resource, getModelStorage().getAllocation()).stream())
                .distinct().collect(Collectors.toList());
        getDataHandler().addData(dataList);
    }

    protected abstract Optional<CompromisedResource> attackResourceContainer(ResourceContainer container,
            CredentialChange change, EObject source);

    private Collection<CompromisedResource> filterExsiting(final Collection<CompromisedResource> containers,
            final CredentialChange change) {
        return containers.stream().filter(container -> !contains(container, change)).collect(Collectors.toList());

    }

    private boolean contains(final CompromisedResource resource, final CredentialChange change) {
        return change.getCompromisedresource().stream().anyMatch(referenceContainer -> EcoreUtil
                .equals(referenceContainer.getAffectedElement(), resource.getAffectedElement()));
    }

}
