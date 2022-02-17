package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Role;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.DefaultSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.RoleSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.HelperUpdateCredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class Change<T> {

    protected Collection<T> initialMarkedItems;

    protected BlackboardWrapper modelStorage;

    protected CredentialChange changes;

    protected AttackGraph attackGraph;
    
    private int stackIndex;

    public Change(final BlackboardWrapper v, final CredentialChange change, final AttackGraph attackGraph) {
        this.modelStorage = v;
        this.initialMarkedItems = this.loadInitialMarkedItems();
        this.changes = change;
        this.attackGraph = attackGraph;
        this.stackIndex = 0;
    }

    protected abstract Collection<T> loadInitialMarkedItems();

    public CredentialChange getChanges() {
        return this.changes;
    }

    protected AttackGraph getAttackGraph() {
        return this.attackGraph;
    }

    protected void updateFromContextProviderStream(final CredentialChange changes,
            final Stream<? extends PCMAttributeProvider> streamAttributeProvider) {
        final var streamContextChange = streamAttributeProvider.map(e -> {
            if (e.getAssemblycontext() != null) {
                return HelperUpdateCredentialChange.createContextChange(e.getAttribute(),
                        List.of(e.getAssemblycontext()));
            }
            if (e.getLinkingresource() != null) {
                return HelperUpdateCredentialChange.createContextChange(e.getAttribute(),
                        List.of(e.getLinkingresource()));
            }
            if (e.getResourcecontainer() != null) {
                return HelperUpdateCredentialChange.createContextChange(e.getAttribute(),
                        List.of(e.getResourcecontainer()));
            }
            return HelperUpdateCredentialChange.createContextChange(e.getAttribute(), null);
        });

        HelperUpdateCredentialChange.updateCredentials(changes, streamContextChange);
    }

    protected Attacker getAttacker() {
        if (this.modelStorage.getModificationMarkRepository().getSeedModifications().getAttackcomponent().isEmpty()) {
            throw new IllegalStateException("No attacker selected");
        }
        if (this.modelStorage.getModificationMarkRepository().getSeedModifications().getAttackcomponent().size() > 2) {
            throw new IllegalStateException("More than one attacker");
        }
        return this.modelStorage.getModificationMarkRepository().getSeedModifications().getAttackcomponent().get(0)
                .getAffectedElement();
    }

    /*TODO remove protected void compromise(final AttackStatusNodeContent selectedNode, final String causeId,
            final AttackStatusNodeContent attackSource) { //TODO do in handlers! //TODO remove here, is now in graph
        Objects.requireNonNull(selectedNode);
        Objects.requireNonNull(attackSource);

        selectedNode.setCompromised(true);
        //TODO attackSource.setAttackSourceOf(selectedNode); //TODO s.above
        generateAllFoundAttackPaths(this.attackGraph.getRootNodeContent());
    }*/

    protected boolean isCompromised(final Entity... entities) {
        return this.attackGraph.isAnyCompromised(entities);
    }
    
    protected void callRecursionIfNecessary(final AttackStatusNodeContent childNode, 
            final Runnable recursionMethod, final AttackStatusNodeContent selectedNode) {
        selectedNode.setVisited(true);
        if (childNode != null && !childNode.isVisited()) {
            // select the child node and recursively call the propagation call
            this.attackGraph.setSelectedNode(childNode);
            this.stackIndex++;
            recursionMethod.run();
            childNode.setVisited(true);
            this.stackIndex--;
            this.attackGraph.setSelectedNode(selectedNode);
        }
    }
    
    protected ResourceContainer getResourceContainerForElement(
            final AttackStatusNodeContent selectedNodeContent) {
        final var selectedElementType = selectedNodeContent.getTypeOfContainedElement();
        final var selectedPCMElement = selectedNodeContent.getContainedElementAsPCMElement();

        final ResourceContainer ret;
        switch (selectedElementType) {
        case ASSEMBLY_CONTEXT:
            final var selectedAssembly = selectedPCMElement.getAssemblycontext();
            final var containerOfSelected = getResourceContainer(selectedAssembly);
            ret = containerOfSelected;
            break;
        case RESOURCE_CONTAINER:
            final var selectedContainer = selectedPCMElement.getResourcecontainer();
            ret = selectedContainer;
            break;
        default:
            // TODO implement all possible cases

            ret = null; // TODO
            break;
        }
        return ret;
    }

    protected ResourceContainer getResourceContainer(final AssemblyContext component) {
        final var allocationOPT = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                .filter(allocation -> EcoreUtil.equals(allocation.getAssemblyContext_AllocationContext(), component))
                .findAny();
        if (allocationOPT.isEmpty()) {
            throw new IllegalStateException(
                    "No Allocation for assemblycontext " + component.getEntityName() + " found");
        }
        return allocationOPT.get().getResourceContainer_AllocationContext();
    }
    
    protected AttackStatusNodeContent getResourceContainerNode(final ResourceContainer resourceContainer,
            final AttackStatusNodeContent selectedNode) {
        final boolean isSelectedNodeAlreadyResourceContainerNode = selectedNode
                .getContainedElement().getId()
                .equals(resourceContainer.getId());
        return isSelectedNodeAlreadyResourceContainerNode 
                    ? selectedNode
                    : this.getAttackGraph().addOrFindChild(selectedNode, new AttackStatusNodeContent(resourceContainer));
    }

    protected List<LinkingResource> getLinkingResource(final ResourceContainer container) {
        final var resourceEnvironment = this.modelStorage.getResourceEnvironment();
        return resourceEnvironment.getLinkingResources__ResourceEnvironment().stream()
                .filter(e -> e.getConnectedResourceContainers_LinkingResource().stream()
                        .anyMatch(f -> EcoreUtil.equals(f, container)))
                .collect(Collectors.toList());
    }

    protected List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource) {
        final var resources = this.getLinkingResource(resource).stream()
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream()).distinct()
                .filter(e -> !EcoreUtil.equals(e, resource)).collect(Collectors.toList());
        return resources;
    }
}
