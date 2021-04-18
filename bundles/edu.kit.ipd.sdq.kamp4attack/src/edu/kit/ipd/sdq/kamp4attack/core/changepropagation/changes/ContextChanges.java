package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.context.model.ContextAttribute;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.system.System;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

@Deprecated
public class ContextChanges extends Change<ContextAttribute> {

    public ContextChanges(final BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<ContextAttribute> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, ContextAttribute.class);
    }

    public void calculateContextToAssemblyPropagation(final CredentialChange changes) {
        final var contexts = this.getContexts(changes);

        final var assembly = changes.getCompromisedassembly().stream().map(CompromisedAssembly::getAffectedElement)
                .collect(Collectors.toList());

        final var setAttacked = new HashSet<AssemblyContext>();
        // Assembly2Assembly
        for (final var component : assembly) {
            final var listAttacked = this.propagateFromAssemblyContext(contexts, component);
            setAttacked.addAll(listAttacked);
        }
        // Assembly
        for (final var component : assembly) {
            final var listAttacked = this.propagateFromAssemblyContextwithOperations(contexts, component);
            setAttacked.addAll(listAttacked);
        }
        for (final var component : setAttacked) {
            final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
            change.setToolderived(true);
            change.setAffectedElement(component);
            if (changes.getCompromisedassembly().stream()
                    .noneMatch(e -> EcoreUtil.equals(e.getAffectedElement(), change.getAffectedElement()))) {
                changes.getCompromisedassembly().add(change);
                changes.setChanged(true);
            }
        }

    }

    private List<ContextAttribute> getContexts(final CredentialChange changes) {
        return changes.getContextchange().stream().map(ContextChange::getAffectedElement).collect(Collectors.toList());
    }

    public void calculateContextToResourcePropagation(final CredentialChange changes) {
        final var contexts = this.getContexts(changes);

        final var ressources = changes.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
                .collect(Collectors.toList());

        final var setAttacked = new HashSet<ResourceContainer>();
        for (final var container : ressources) {
            final var attacks = this.propagateFromRessourceContainer(contexts, container);
            setAttacked.addAll(attacks);
        }
        this.addHackedResources(changes, setAttacked);
    }

    private void addHackedResources(final CredentialChange changes, final Collection<ResourceContainer> setAttacked) {
        for (final var container : setAttacked) {
            final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
            change.setToolderived(true);
            change.setAffectedElement(container);
            if (changes.getCompromisedresource().stream()
                    .noneMatch(e -> EcoreUtil.equals(e.getAffectedElement(), change.getAffectedElement()))) {
                changes.getCompromisedresource().add(change);
                changes.setChanged(true);
            }
        }
    }

    public void calculateContextToLinkingPropagation(final CredentialChange changes) {
        final var contexts = this.createContextSet(this.getContexts(changes));
        final var resources = changes.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
                .collect(Collectors.toList());

        // calculate Resourcecontainer executing AssemblyContexts
        final var listCompromisedAssemblyContexts = changes.getCompromisedassembly().stream()
                .map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());

        final var streamTargetAllocations = this.modelStorage.getAllocation().getAllocationContexts_Allocation()
                .stream().filter(e -> listCompromisedAssemblyContexts.stream()
                        .anyMatch(f -> EcoreUtil.equals(f, e.getAssemblyContext_AllocationContext())));

        final var listResourceContainer = streamTargetAllocations
                .map(AllocationContext::getResourceContainer_AllocationContext).collect(Collectors.toList());

        resources.addAll(listResourceContainer);

        final var attackableLinkingResources = resources.stream().flatMap(this::getLinkingResourcePrivate)
                .collect(Collectors.toList());

        final var compromisedLinkingResources = attackableLinkingResources.stream()
                .filter(e -> this.attackLinkingResource(e, contexts)).collect(Collectors.toList());

        for (final var linking : compromisedLinkingResources) {
            final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedLinkingResource();
            change.setToolderived(true);
            change.setAffectedElement(linking);
            if (changes.getCompromisedlinkingresource().stream()
                    .noneMatch(e -> EcoreUtil.equals(e.getAffectedElement(), change.getAffectedElement()))) {
                changes.getCompromisedlinkingresource().add(change);
                changes.setChanged(true);
            }
        }

    }

    public void calculateContextLinkingToResourcePropagation(final CredentialChange changes) {
        final var contexts = this.createContextSet(this.getContexts(changes));
        final var listCompromisedLinkingResources = changes.getCompromisedlinkingresource().stream()
                .map(CompromisedLinkingResource::getAffectedElement).collect(Collectors.toList());
        final var hackableContainers = listCompromisedLinkingResources.stream()
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream())
                .filter(e -> this.attackResourceContainer(e, contexts)).collect(Collectors.toList());

        this.addHackedResources(changes, hackableContainers);
    }

    private Set<ResourceContainer> propagateFromRessourceContainer(final List<ContextAttribute> contexts,
            final ResourceContainer container) {

        final var set = this.createContextSet(contexts);
        final var streamReachableContainer = this.getLinkingResourcePrivate(container)
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream());

        return streamReachableContainer.filter(e -> this.attackResourceContainer(e, set)).collect(Collectors.toSet());

    }

    private Stream<LinkingResource> getLinkingResourcePrivate(final ResourceContainer container) {
        final var resourceEnvironment = this.modelStorage.getResourceEnvironment();
        return resourceEnvironment.getLinkingResources__ResourceEnvironment().stream()
                .filter(e -> e.getConnectedResourceContainers_LinkingResource().stream()
                        .anyMatch(f -> EcoreUtil.equals(f, container)));
    }

    private Set<AssemblyContext> propagateFromAssemblyContextwithOperations(final List<ContextAttribute> contexts,
            final AssemblyContext component) {
        final var system = this.modelStorage.getAssembly();
        final var set = this.createContextSet(contexts);
        final var targetConnectors = this.getTargetedConnectors(component, system);

        final var attackedConnectors = targetConnectors.stream()
                .filter(e -> this.getPolicyStream().filter(policy -> policy.getMethodspecification() != null)
                        .filter(policy -> EcoreUtil.equals(policy.getMethodspecification().getConnector(), e))
                        .flatMap(policy -> policy.getPolicy().stream())
                        .anyMatch(policy -> policy.checkAccessRight(set)))
                .collect(Collectors.toList());

        final var targetComponents = attackedConnectors.stream()
                .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector).collect(Collectors.toSet());

        targetComponents.addAll(attackedConnectors.stream()
                .map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector).collect(Collectors.toSet()));

        return targetComponents;
    }

    private Set<AssemblyContext> propagateFromAssemblyContext(final List<ContextAttribute> contexts,
            final AssemblyContext component) {
        final var system = this.modelStorage.getAssembly();
        final var set = this.createContextSet(contexts);
        // TODO simplify stream expression directly to components!
        final var targetConnectors = this.getTargetedConnectors(component, system);

        final var targetComponents = targetConnectors.stream()
                .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector).collect(Collectors.toList());

        targetComponents.addAll(targetConnectors.stream()
                .map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector).collect(Collectors.toList()));

        return targetComponents.stream().filter(e -> this.attackAssemblyContext(e, set)).collect(Collectors.toSet());
    }

    private List<AssemblyConnector> getTargetedConnectors(final AssemblyContext component, final System system) {
        return system.getConnectors__ComposedStructure().stream().filter(AssemblyConnector.class::isInstance)
                .map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
                        || EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(), component))
                .collect(Collectors.toList());
    }

    private boolean attackAssemblyContext(final AssemblyContext component, final ContextSet set) {
        final var targetSpecification = this.getPolicyStream()
                .filter(e -> EcoreUtil.equals(e.getAssemblycontext(), component));

        return targetSpecification.flatMap(e -> e.getPolicy().stream()).anyMatch(e -> e.checkAccessRight(set));
    }

    private boolean attackResourceContainer(final ResourceContainer container, final ContextSet set) {
        final var targetResource = this.getPolicyStream()
                .filter(e -> EcoreUtil.equals(e.getResourcecontainer(), container));
        return targetResource.flatMap(e -> e.getPolicy().stream()).anyMatch(e -> e.checkAccessRight(set));
    }

    private boolean attackLinkingResource(final LinkingResource linking, final ContextSet set) {
        final var targetResource = this.getPolicyStream()
                .filter(e -> EcoreUtil.equals(e.getLinkingresource(), linking));
        return targetResource.flatMap(e -> e.getPolicy().stream()).anyMatch(e -> e.checkAccessRight(set));
    }

}
