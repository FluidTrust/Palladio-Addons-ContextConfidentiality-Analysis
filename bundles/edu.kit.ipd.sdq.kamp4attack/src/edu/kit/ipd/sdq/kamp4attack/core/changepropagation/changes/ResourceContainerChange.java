package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.CollectionHelper;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.HelperCreationCompromisedElements;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class ResourceContainerChange extends Change<ResourceContainer>
        implements ResourceContainerPropagation {

    public ResourceContainerChange(final BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<ResourceContainer> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, ResourceContainer.class);
    }

    private List<ResourceContainer> getInfectedResourceContainers(final CredentialChange changes) {
        return changes.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
                .collect(Collectors.toList());
    }

    @Override
    public void calculateResourceContainerToContextPropagation(final CredentialChange changes) {
        final var listInfectedContainer = this.getInfectedResourceContainers(changes);

        final var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream().filter(
                e -> listInfectedContainer.stream().anyMatch(f -> EcoreUtil.equals(e.getResourcecontainer(), f)));

        this.updateFromContextProviderStream(changes, streamAttributeProvider);
    }

    @Override
    public void calculateResourceContainerToRemoteAssemblyContextPropagation(final CredentialChange changes) {
        final var listInfectedContainer = this.getInfectedResourceContainers(changes);

        for (final var resource : listInfectedContainer) {
            final var resources = this.getConnectedResourceContainers(resource);
            final var assemblycontext = CollectionHelper.getAssemblyContext(resources,
                    this.modelStorage.getAllocation());
            final var handler = this.getAssemblyHandler();
            handler.attackAssemblyContext(assemblycontext, changes, resource);
        }

    }

    protected abstract AssemblyContextHandler getAssemblyHandler();

    @Override
    public void calculateResourceContainerToLocalAssemblyContextPropagation(final CredentialChange changes) {
        final var listInfectedContainer = this.getInfectedResourceContainers(changes);

        for (final var resource : listInfectedContainer) {
            final var localComponents = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                    .filter(e -> EcoreUtil.equals(resource, e.getResourceContainer_AllocationContext()))
                    .map(AllocationContext::getAssemblyContext_AllocationContext);

            final var streamChanges = localComponents
                    .map(e -> HelperCreationCompromisedElements.createCompromisedAssembly(e, List.of(resource)));

            final var listChanges = streamChanges
                    .filter(e -> changes.getCompromisedassembly().stream()
                            .noneMatch(f -> EcoreUtil.equals(f.getAffectedElement(), e.getAffectedElement())))
                    .collect(Collectors.toList());

            changes.getCompromisedassembly().addAll(listChanges);
            if (!listChanges.isEmpty()) {
                changes.setChanged(true);
            }
        }
    }

    @Override
    public void calculateResourceContainerToResourcePropagation(final CredentialChange changes) {
        final var listInfectedContainer = this.getInfectedResourceContainers(changes);

        for (final var resource : listInfectedContainer) {
            final var resources = this.getConnectedResourceContainers(resource);

            final var handler = this.getResourceHandler();
            handler.attackResourceContainer(resources, changes, resource);
        }

    }

    private List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource) {
        final var resources = this.getLinkingResource(resource).stream()
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream()).distinct()
                .filter(e -> !EcoreUtil.equals(e, resource)).collect(Collectors.toList());
        return resources;
    }

    protected abstract ResourceContainerHandler getResourceHandler();

    @Override
    public void calculateResourceContainerToLinkingResourcePropagation(final CredentialChange changes) {
        final var listInfectedContainer = this.getInfectedResourceContainers(changes);

        for (final var resource : listInfectedContainer) {
            final var linkinResources = this.getLinkingResource(resource);
            final var handler = this.getLinkingHandler();
            handler.attackLinkingResource(linkinResources, changes, resource);
        }

    }

    protected abstract LinkingResourceHandler getLinkingHandler();

}
