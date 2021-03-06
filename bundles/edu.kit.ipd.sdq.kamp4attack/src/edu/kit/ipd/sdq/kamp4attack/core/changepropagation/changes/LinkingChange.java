package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.CollectionHelper;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.LinkingPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class LinkingChange extends Change<LinkingResource> implements LinkingPropagation {

    public LinkingChange(final BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<LinkingResource> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, LinkingResource.class);
    }

    @Override
    public void calculateLinkingResourceToContextPropagation(final CredentialChange changes) {
        final var listCompromisedLinkingResources = changes.getCompromisedlinkingresource().stream()
                .map(CompromisedLinkingResource::getAffectedElement).collect(Collectors.toList());

        final var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
                .filter(e -> listCompromisedLinkingResources.stream()
                        .anyMatch(f -> EcoreUtil.equals(e.getLinkingresource(), f)));

        updateFromContextProviderStream(changes, streamAttributeProvider);

    }

    @Override
    public void calculateLinkingResourceToResourcePropagation(final CredentialChange changes) {
        final var compromisedLinkingResources = getCompromisedLinkingResources(changes);
        for (final var linking : compromisedLinkingResources) {
            final var reachableResources = linking.getConnectedResourceContainers_LinkingResource();
            final var handler = getResourceContainerHandler();
            handler.attackResourceContainer(reachableResources, changes, linking);
        }

    }

    protected abstract ResourceContainerHandler getResourceContainerHandler();

    protected abstract AssemblyContextHandler getAssemblyContextHandler();

    @Override
    public void calculateLinkingResourceToAssemblyContextPropagation(final CredentialChange changes) {
        final var compromisedLinkingResources = getCompromisedLinkingResources(changes);

        for (final var linking : compromisedLinkingResources) {
            final var reachableResources = linking.getConnectedResourceContainers_LinkingResource();
            var reachableAssemblies = CollectionHelper.getAssemblyContext(reachableResources,
                    this.modelStorage.getAllocation());
            final var handler = getAssemblyContextHandler();
            reachableAssemblies = CollectionHelper.removeDuplicates(reachableAssemblies);
            handler.attackAssemblyContext(reachableAssemblies, changes, linking);
            handleSeff(changes, reachableAssemblies, linking);

        }
    }

    protected abstract void handleSeff(CredentialChange changes, List<AssemblyContext> components,
            LinkingResource source);

    protected List<LinkingResource> getCompromisedLinkingResources(final CredentialChange changes) {
        return changes.getCompromisedlinkingresource().stream().map(CompromisedLinkingResource::getAffectedElement)
                .collect(Collectors.toList());
    }

}
