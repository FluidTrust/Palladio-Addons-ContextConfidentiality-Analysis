package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.model.ContextAttribute;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
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
            if (!changes.getCompromisedassembly().stream()
                    .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(), change.getAffectedElement()))) {
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
        for (var container : setAttacked) {
            var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
            change.setToolderived(true);
            change.setAffectedElement(container);
            if (!changes.getCompromisedresource().stream()
                    .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(), change.getAffectedElement()))) {
                changes.getCompromisedresource().add(change);
                changes.setChanged(true);
            }
        }
    }

    private Set<ResourceContainer> propagateFromRessourceContainer(List<ContextAttribute> contexts,
            ResourceContainer container) {
        var resourceEnvironment = this.modelStorage.getResourceEnvironment();
        var set = createContextSet(contexts);
        var streamReachableContainer = resourceEnvironment.getLinkingResources__ResourceEnvironment().stream()
                .filter(e -> {
                    return e.getConnectedResourceContainers_LinkingResource().stream()
                            .anyMatch(f -> EcoreUtil.equals(f, container));
                }).flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream());

        return streamReachableContainer.filter(e -> getContextList(e, set)).collect(Collectors.toSet());

    }

    private Set<AssemblyContext> propagateFromAssemblyContext(List<ContextAttribute> contexts,
            AssemblyContext component) {
        var system = this.modelStorage.getAssembly();
        var set = createContextSet(contexts);
        var targetConnectors = system.getConnectors__ComposedStructure().stream()
                .filter(AssemblyConnector.class::isInstance).map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiredRole_AssemblyConnector(), component))
                .collect(Collectors.toList());

        var targetComponents = targetConnectors.stream()
                .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector).collect(Collectors.toList());

        return targetComponents.stream().filter(e -> getContextList(e, set)).collect(Collectors.toSet());
    }

    private boolean getContextList(AssemblyContext component, ContextSet set) {
        var targetSpecification = getPolicyStream().filter(e -> EcoreUtil.equals(e.getAssemblycontext(), component));

        return targetSpecification.flatMap(e -> e.getPolicy().stream()).anyMatch(e -> e.checkAccessRight(set));
    }

    private boolean getContextList(ResourceContainer container, ContextSet set) {
        var targetResource = getPolicyStream().filter(e -> EcoreUtil.equals(e.getResourcecontainer(), container));
        return targetResource.flatMap(e -> e.getPolicy().stream()).anyMatch(e -> e.checkAccessRight(set));
    }



}
