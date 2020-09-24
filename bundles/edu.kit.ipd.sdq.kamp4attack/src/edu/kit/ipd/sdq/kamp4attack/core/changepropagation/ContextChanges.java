package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

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

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class ContextChanges extends Change<ContextAttribute> {

    public ContextChanges(BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<ContextAttribute> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(modelStorage, ContextAttribute.class);
    }

    public void calculateContextToAssemblyPropagation(CredentialChange changes) {
        var contexts = getContexts(changes);

        var assembly = changes.getCompromisedassembly().stream().map(CompromisedAssembly::getAffectedElement)
                .collect(Collectors.toList());

        var setAttacked = new HashSet<AssemblyContext>();
        for (var component : assembly) {
            var listAttacked = propagateFromAssemblyContext(contexts, component);
            setAttacked.addAll(listAttacked);
        }
        for (var component : setAttacked) {
            var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
            change.setToolderived(true);
            change.setAffectedElement(component);
            if (changes.getCompromisedassembly().stream()
                    .noneMatch(e -> EcoreUtil.equals(e.getAffectedElement(), change.getAffectedElement()))) {
                changes.getCompromisedassembly().add(change);
                changes.setChanged(true);
            }
        }

    }

    private List<ContextAttribute> getContexts(CredentialChange changes) {
        return changes.getContextchange().stream().map(ContextChange::getAffectedElement).collect(Collectors.toList());
    }

    public void calculateContextToResourcePropagation(CredentialChange changes) {
        var contexts = getContexts(changes);

        var ressources = changes.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
                .collect(Collectors.toList());

        var setAttacked = new HashSet<ResourceContainer>();
        for (var container : ressources) {
            var attacks = propagateFromRessourceContainer(contexts, container);
            setAttacked.addAll(attacks);
        }
        addHackedResources(changes, setAttacked);
    }

    private void addHackedResources(CredentialChange changes, Collection<ResourceContainer> setAttacked) {
        for (var container : setAttacked) {
            var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
            change.setToolderived(true);
            change.setAffectedElement(container);
            if (changes.getCompromisedresource().stream()
                    .noneMatch(e -> EcoreUtil.equals(e.getAffectedElement(), change.getAffectedElement()))) {
                changes.getCompromisedresource().add(change);
                changes.setChanged(true);
            }
        }
    }

    public void calculateContextToLinkingPropagation(CredentialChange changes) {
        var contexts = createContextSet(getContexts(changes));
        var resources = changes.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
                .collect(Collectors.toList());

        // calculate Resourcecontainer executing AssemblyContexts
        var listCompromisedAssemblyContexts = changes.getCompromisedassembly().stream()
                .map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());

        var streamTargetAllocations = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                .filter(e -> listCompromisedAssemblyContexts.stream()
                        .anyMatch(f -> EcoreUtil.equals(f, e.getAssemblyContext_AllocationContext())));

        var listResourceContainer = streamTargetAllocations
                .map(AllocationContext::getResourceContainer_AllocationContext).collect(Collectors.toList());
       

        resources.addAll(listResourceContainer);

        var attackableLinkingResources = resources.stream().flatMap(this::getLinkingResource)
                .collect(Collectors.toList());

        var compromisedLinkingResources = attackableLinkingResources.stream()
                .filter(e -> attackLinkingResource(e, contexts)).collect(Collectors.toList());

        for (var linking : compromisedLinkingResources) {
            var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedLinkingResource();
            change.setToolderived(true);
            change.setAffectedElement(linking);
            if (changes.getCompromisedlinkingresource().stream()
                    .noneMatch(e -> EcoreUtil.equals(e.getAffectedElement(), change.getAffectedElement()))) {
                changes.getCompromisedlinkingresource().add(change);
                changes.setChanged(true);
            }
        }

    }

    public void calculateContextLinkingToResourcePropagation(CredentialChange changes) {
        var contexts = createContextSet(getContexts(changes));
        var listCompromisedLinkingResources = changes.getCompromisedlinkingresource().stream()
                .map(CompromisedLinkingResource::getAffectedElement).collect(Collectors.toList());
        var hackableContainers = listCompromisedLinkingResources.stream()
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream())
                .filter(e -> attackResourceContainer(e, contexts)).collect(Collectors.toList());

        addHackedResources(changes, hackableContainers);
    }

    private Set<ResourceContainer> propagateFromRessourceContainer(List<ContextAttribute> contexts,
            ResourceContainer container) {

        var set = createContextSet(contexts);
        var streamReachableContainer = getLinkingResource(container)
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream());

        return streamReachableContainer.filter(e -> attackResourceContainer(e, set)).collect(Collectors.toSet());

    }

    private Stream<LinkingResource> getLinkingResource(ResourceContainer container) {
        var resourceEnvironment = this.modelStorage.getResourceEnvironment();
        return resourceEnvironment.getLinkingResources__ResourceEnvironment().stream()
                .filter(e -> e.getConnectedResourceContainers_LinkingResource().stream()
                        .anyMatch(f -> EcoreUtil.equals(f, container)));
    }

    private Set<AssemblyContext> propagateFromAssemblyContext(List<ContextAttribute> contexts,
            AssemblyContext component) {
        var system = this.modelStorage.getAssembly();
        var set = createContextSet(contexts);
        // TODO simplify stream expression directly to components!
        var targetConnectors = system.getConnectors__ComposedStructure().stream()
                .filter(AssemblyConnector.class::isInstance).map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
                        || EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(), component))
                .collect(Collectors.toList());

        var targetComponents = targetConnectors.stream()
                .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector).collect(Collectors.toList());

        targetComponents.addAll(targetConnectors.stream()
                .map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector).collect(Collectors.toList()));

        return targetComponents.stream().filter(e -> attackAssemblyContext(e, set)).collect(Collectors.toSet());
    }

    private boolean attackAssemblyContext(AssemblyContext component, ContextSet set) {
        var targetSpecification = getPolicyStream().filter(e -> EcoreUtil.equals(e.getAssemblycontext(), component));

        return targetSpecification.flatMap(e -> e.getPolicy().stream()).anyMatch(e -> e.checkAccessRight(set));
    }

    private boolean attackResourceContainer(ResourceContainer container, ContextSet set) {
        var targetResource = getPolicyStream().filter(e -> EcoreUtil.equals(e.getResourcecontainer(), container));
        return targetResource.flatMap(e -> e.getPolicy().stream()).anyMatch(e -> e.checkAccessRight(set));
    }

    private boolean attackLinkingResource(LinkingResource linking, ContextSet set) {
        var targetResource = getPolicyStream().filter(e -> EcoreUtil.equals(e.getLinkingresource(), linking));
        return targetResource.flatMap(e -> e.getPolicy().stream()).anyMatch(e -> e.checkAccessRight(set));
    }

}
