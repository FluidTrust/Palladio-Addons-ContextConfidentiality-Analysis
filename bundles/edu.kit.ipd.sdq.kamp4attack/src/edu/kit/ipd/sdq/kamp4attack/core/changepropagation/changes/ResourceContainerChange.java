package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.ResourceContainerChangeAssemblyContextsStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagationWithContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class ResourceContainerChange extends Change<ResourceContainer>
        implements ResourceContainerPropagationWithContext {

    public ResourceContainerChange(final BlackboardWrapper v, CredentialChange change) {
        super(v, change);
    }

    protected List<ResourceContainer> getInfectedResourceContainers() {
        return this.changes.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
                .collect(Collectors.toList());
    }

    @Override
    public void calculateResourceContainerToContextPropagation() {
        final var listInfectedContainer = getInfectedResourceContainers();

        final var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
                .filter(PCMAttributeProvider.class::isInstance).map(PCMAttributeProvider.class::cast)
                .filter(e -> listInfectedContainer.stream()
                        .anyMatch(f -> EcoreUtil.equals(e.getResourcecontainer(), f)));

        updateFromContextProviderStream(this.changes, streamAttributeProvider);
    }

    @Override
    public void calculateResourceContainerToRemoteAssemblyContextPropagation() {
        final var listInfectedContainer = getInfectedResourceContainers();

        var storage = ResourceContainerChangeAssemblyContextsStorage.getInstance();

        for (final var resource : listInfectedContainer) {
            final var resources = getConnectedResourceContainers(resource);

            // Uses a HashMap to store results, to avoid recalculation and improve
            // performance
            if (!storage.contains(resource.getId())) {
                var assemblycontext = CollectionHelper.getAssemblyContext(resources, this.modelStorage.getAllocation());
                assemblycontext = CollectionHelper.removeDuplicates(assemblycontext).stream()
                        .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
                storage.put(resource.getId(), assemblycontext);
            }

            var assemblycontext = storage.get(resource.getId());

            final var handler = getAssemblyHandler();
            handler.attackAssemblyContext(assemblycontext, this.changes, resource);
            handleSeff(this.changes, assemblycontext, resource);
        }

    }

    protected abstract void handleSeff(CredentialChange changes, List<AssemblyContext> components,
            ResourceContainer source);

    protected abstract AssemblyContextHandler getAssemblyHandler();

    @Override
    public void calculateResourceContainerToLocalAssemblyContextPropagation() {
        final var listInfectedContainer = getInfectedResourceContainers();

        for (final var resource : listInfectedContainer) {
            final var localComponents = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                    .filter(e -> EcoreUtil.equals(resource, e.getResourceContainer_AllocationContext()))
                    .map(AllocationContext::getAssemblyContext_AllocationContext)
                    .filter(e -> !CacheCompromised.instance().compromised(e));

            final var streamChanges = localComponents
                    .map(e -> HelperCreationCompromisedElements.createCompromisedAssembly(e, List.of(resource)));

            final var listChanges = streamChanges
                    .filter(e -> this.changes.getCompromisedassembly().stream()
                            .noneMatch(f -> EcoreUtil.equals(f.getAffectedElement(), e.getAffectedElement())))
                    .collect(Collectors.toList());

            if (!listChanges.isEmpty()) {
                this.changes.getCompromisedassembly().addAll(listChanges);
                CollectionHelper.addService(listChanges, this.modelStorage.getVulnerabilitySpecification(),
                        this.changes);
                final var dataList = listChanges.stream().distinct().map(CompromisedAssembly::getAffectedElement)
                        .flatMap(component -> DataHandler.getData(component).stream()).collect(Collectors.toList());
                new DataHandlerAttacker(this.changes).addData(dataList);

                this.changes.setChanged(true);
            }
        }
    }

    @Override
    public void calculateResourceContainerToResourcePropagation() {
        final var listInfectedContainer = getInfectedResourceContainers();

        for (final var resource : listInfectedContainer) {
            final var resources = getConnectedResourceContainers(resource).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

            final var handler = getResourceHandler();
            handler.attackResourceContainer(resources, this.changes, resource);
        }

    }

    protected abstract ResourceContainerHandler getResourceHandler();

    @Override
    public void calculateResourceContainerToLinkingResourcePropagation() {
        final var listInfectedContainer = getInfectedResourceContainers();

        for (final var resource : listInfectedContainer) {
            final var linkinResources = getLinkingResource(resource).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            final var handler = getLinkingHandler();
            handler.attackLinkingResource(linkinResources, this.changes, resource);
        }

    }

    protected abstract LinkingResourceHandler getLinkingHandler();

}
