package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.attackdag.AttackDAG;
import edu.kit.ipd.sdq.attacksurface.attackdag.AttackStatusDescriptorNodeContent;
import edu.kit.ipd.sdq.attacksurface.attackdag.Node;
import edu.kit.ipd.sdq.attacksurface.attackdag.PCMElementType;
import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class ResourceContainerChange extends Change<ResourceContainer>
        implements ResourceContainerPropagation {
    public ResourceContainerChange(final BlackboardWrapper v, CredentialChange change, final AttackDAG attackDAG) {
        super(v, change, attackDAG);
    }

    @Override
    protected Collection<ResourceContainer> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, ResourceContainer.class);
    }

    protected List<ResourceContainer> getInfectedResourceContainers() {
        return this.changes.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
                .collect(Collectors.toList());
    }

    @Override
    public void calculateResourceContainerToContextPropagation() {
        // TODO adapt

        /*
         * final var listInfectedContainer = getInfectedResourceContainers();
         * 
         * final var streamAttributeProvider =
         * this.modelStorage.getSpecification().getAttributeprovider().stream()
         * .filter(PCMAttributeProvider.class::isInstance).map(PCMAttributeProvider.
         * class::cast) .filter(e -> listInfectedContainer.stream() .anyMatch(f ->
         * EcoreUtil.equals(e.getResourcecontainer(), f)));
         * 
         * updateFromContextProviderStream(this.changes, streamAttributeProvider);
         */
    }

    @Override
    public void calculateResourceContainerToRemoteAssemblyContextPropagation() {
        final var listInfectedContainers = getInfectedResourceContainers();

        final var selectedNode = this.attackDAG.getSelectedNode();
        final var selectedEntity = selectedNode.getContent().getContainedElement();

        final var relevantResourceContainer = getResourceContainerForElement(selectedNode);
        if (listInfectedContainers.contains(relevantResourceContainer)) {

            final var resources = getConnectedResourceContainers(relevantResourceContainer);
            var assemblycontext = CollectionHelper.getAssemblyContext(Arrays.asList(relevantResourceContainer),
                    this.modelStorage.getAllocation());
            final var handler = getAssemblyHandler();
            assemblycontext = CollectionHelper.removeDuplicates(assemblycontext);
            for (final var resource : resources) {
                final var childNode = selectedNode.addChild(new AttackStatusDescriptorNodeContent(resource));
                if (childNode != null) {
                    // attack all, so that maybe in the next iteration of assembly contexts
                    // propagation
                    // more attacks are possible

                    handler.attackAssemblyContext(assemblycontext, this.changes, resource);
                    if (isCompromised(selectedEntity)) {
                        // handleSeff(this.changes, assemblycontext, resource); //TODO
                        final var resourceContainerNode = getResourceContainerNode(relevantResourceContainer, 
                                selectedNode);
                        compromise(selectedNode, getLastCauseId(selectedEntity), resourceContainerNode);
                    }

                    // select the child node and recursively call the propagation call
                    this.callRecursion(childNode, this::calculateResourceContainerToRemoteAssemblyContextPropagation, 
                            selectedNode);
                }
            }
        }
    }

    protected abstract void handleSeff(CredentialChange changes, List<AssemblyContext> components,
            ResourceContainer source);

    protected abstract AssemblyContextHandler getAssemblyHandler();

    // attack inner assemblies from already compromised res. containers
    @Override
    public void calculateResourceContainerToLocalAssemblyContextPropagation() { 
        final var selectedNode = this.attackDAG.getSelectedNode();
        final var selectedEntity = selectedNode.getContent().getContainedElement();

        final var relevantResourceContainer = getResourceContainerForElement(selectedNode);
        final var listInfectedContainers = getInfectedResourceContainers();
        if (listInfectedContainers.contains(relevantResourceContainer)) {

            final var localComponents = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                    .filter(e -> EcoreUtil.equals(relevantResourceContainer,
                            e.getResourceContainer_AllocationContext()))
                    .map(AllocationContext::getAssemblyContext_AllocationContext).collect(Collectors.toList());

            final var listCompromised = localComponents.stream()
                    .map(e -> HelperCreationCompromisedElements.createCompromisedAssembly(e,
                            List.of(relevantResourceContainer)))
                    /*
                     * .filter(e -> this.changes.getCompromisedassembly().stream() .noneMatch(f ->
                     * EcoreUtil.equals(f.getAffectedElement(), e.getAffectedElement())))
                     */
                    .collect(Collectors.toList()); // TODO remove ^

            if (!listCompromised.isEmpty()) {
                this.changes.getCompromisedassembly().addAll(listCompromised);
                CollectionHelper.addService(listCompromised, this.modelStorage.getVulnerabilitySpecification(),
                        this.changes);
                if (isCompromised(selectedEntity)) {
                    // handleSeff(this.changes, assemblycontext, resource);
                    final var resourceContainerNode = selectedNode
                            .addOrFindChild(new AttackStatusDescriptorNodeContent(relevantResourceContainer));
                    compromise(selectedNode, getLastCauseId(selectedEntity), resourceContainerNode);
                }
            }

            //TODO v move this block out of this if 
            final var connectedResourceContainers = getConnectedResourceContainers(relevantResourceContainer);
            for (final var resource : connectedResourceContainers) {
                final var childNode = selectedNode.addChild(new AttackStatusDescriptorNodeContent(resource));
                if (childNode != null) {
                    this.callRecursion(childNode, this::calculateResourceContainerToLocalAssemblyContextPropagation, 
                            selectedNode);
                }
            }
        }
    }

    private void selfAttack(final ResourceContainer relevantResourceContainer) {
        final var handler = getResourceHandler();
        handler.attackResourceContainer(Arrays.asList(relevantResourceContainer), this.changes,
                relevantResourceContainer);
    }

    @Override
    public void calculateResourceContainerToResourcePropagation() {
        final var selectedNode = this.attackDAG.getSelectedNode();

        final var relevantResourceContainer = getResourceContainerForElement(selectedNode);
        selfAttack(relevantResourceContainer);
        final var relevantResourceContainerNode = getResourceContainerNode(relevantResourceContainer, selectedNode);
        if (isCompromised(relevantResourceContainer)) {
            compromise(relevantResourceContainerNode, getLastCauseId(relevantResourceContainer), relevantResourceContainerNode);
        }

        final var handler = getResourceHandler();
        final var connectedResourceContainers = getConnectedResourceContainers(relevantResourceContainer);
        for (final var resource : connectedResourceContainers) {
            final var childNode = getResourceContainerNode(resource, selectedNode);
            if (childNode != null) {
                handler.attackResourceContainer(Arrays.asList(relevantResourceContainer), this.changes, resource);
                if (isCompromised(relevantResourceContainer)) {
                    compromise(relevantResourceContainerNode, getLastCauseId(relevantResourceContainer), childNode);
                }
            
                // select the child node and recursively call the propagation call
                this.callRecursion(childNode, this::calculateResourceContainerToResourcePropagation, 
                        selectedNode);
            }
        }
    }

    protected abstract ResourceContainerHandler getResourceHandler();

    @Override
    public void calculateResourceContainerToLinkingResourcePropagation() {
        // TODO adapt
        /*
         * final var listInfectedContainer = getInfectedResourceContainers();
         * 
         * for (final var resource : listInfectedContainer) { final var linkinResources
         * = getLinkingResource(resource).stream() .filter(e ->
         * !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
         * final var handler = getLinkingHandler();
         * handler.attackLinkingResource(linkinResources, this.changes, resource); }
         */
    }

    protected abstract LinkingResourceHandler getLinkingHandler();

}
