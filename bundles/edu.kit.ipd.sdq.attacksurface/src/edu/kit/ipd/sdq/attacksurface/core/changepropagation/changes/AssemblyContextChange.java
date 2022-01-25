package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.NonGlobalCommunication;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;
import org.palladiosimulator.pcm.system.System;

import edu.kit.ipd.sdq.attacksurface.attackdag.AttackDAG;
import edu.kit.ipd.sdq.attacksurface.attackdag.AttackStatusDescriptorNodeContent;
import edu.kit.ipd.sdq.attacksurface.attackdag.Node;
import edu.kit.ipd.sdq.attacksurface.core.AttackSurfaceAnalysis;
import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.Change;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public abstract class AssemblyContextChange extends Change<AssemblyContext> implements AssemblyContextPropagation {
    private AttackDAG attackDAG;
    private int index;

    protected AssemblyContextChange(final BlackboardWrapper v, final CredentialChange change,
            final AttackDAG attackDAG) {
        super(v, change);
        this.attackDAG = attackDAG;
        this.index = 0;
    }

    @Override
    protected Collection<AssemblyContext> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, AssemblyContext.class);
    }

    protected List<AssemblyContext> getCompromisedAssemblyContexts() {
        return this.changes.getCompromisedassembly().stream().map(CompromisedAssembly::getAffectedElement)
                .collect(Collectors.toList());
    }

    @Override
    public void calculateAssemblyContextToContextPropagation() {
        //TODO adapt
        
        final var listCompromisedAssemblyContexts = getCompromisedAssemblyContexts();

        final var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
                .filter(PCMAttributeProvider.class::isInstance).map(PCMAttributeProvider.class::cast)
                .filter(e -> listCompromisedAssemblyContexts.stream()
                        .anyMatch(f -> EcoreUtil.equals(e.getAssemblycontext(), f)));

        updateFromContextProviderStream(this.changes, streamAttributeProvider);

    }

    @Override
    public void calculateAssemblyContextToRemoteResourcePropagation() {
        //TODO adapt
        
        final var listCompromisedContexts = getCompromisedAssemblyContexts();

        for (final var component : listCompromisedContexts) {
            final var connected = getConnectedComponents(component);
            final var containers = connected.stream().map(this::getResourceContainer).distinct()
                    .collect(Collectors.toList());
            final var handler = getRemoteResourceHandler();
            handler.attackResourceContainer(containers, this.changes, component);
        }

    }

    private void handleSeff(final AssemblyContext sourceComponent) {
        final var system = this.modelStorage.getAssembly();
        // TODO simplify stream expression directly to components!
        final var targetConnectors = getSourcedConnectors(sourceComponent, system);

        final var specification = targetConnectors.stream()
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), sourceComponent))
                .flatMap(role -> {

                    final var signatures = role.getProvidedRole_AssemblyConnector()
                            .getProvidedInterface__OperationProvidedRole().getSignatures__OperationInterface();

                    final var componentRepository = role.getProvidingAssemblyContext_AssemblyConnector()
                            .getEncapsulatedComponent__AssemblyContext();

                    if (componentRepository instanceof BasicComponent) {
                        final var basicComponent = (BasicComponent) componentRepository;
                        return basicComponent.getServiceEffectSpecifications__BasicComponent().stream()
                                .filter(seff -> signatures.stream().anyMatch( // find only seff of
                                        // role
                                        signature -> EcoreUtil.equals(signature, seff.getDescribedService__SEFF())))

                                .map(seff -> {
                                    final var methodspecification = StructureFactory.eINSTANCE
                                            .createServiceRestriction();
                                    methodspecification
                                            .setAssemblycontext(role.getProvidingAssemblyContext_AssemblyConnector());
                                    methodspecification.setService((ResourceDemandingSEFF) seff);
                                    methodspecification
                                            .setSignature(methodspecification.getService().getDescribedService__SEFF());
                                    return methodspecification;
                                });

                    }
                    return Stream.empty();
                }).collect(Collectors.toList());
        this.handleSeff(this.changes, specification, sourceComponent);
    }

    protected abstract void handleSeff(CredentialChange changes, List<ServiceRestriction> services,
            AssemblyContext source);

    @Override
    public void calculateAssemblyContextToLocalResourcePropagation() {
        //TODO adapt
        
        final var listCompromisedContexts = getCompromisedAssemblyContexts();

        for (final var component : listCompromisedContexts) {
            final var resource = getResourceContainer(component);
            final var handler = getLocalResourceHandler();
            handler.attackResourceContainer(List.of(resource), this.changes, component);
        }

    }

    private ResourceContainer getResourceContainer(final AssemblyContext component) {
        final var allocationOPT = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                .filter(allocation -> EcoreUtil.equals(allocation.getAssemblyContext_AllocationContext(), component))
                .findAny();
        if (allocationOPT.isEmpty()) {
            throw new IllegalStateException(
                    "No Allocation for assemblycontext " + component.getEntityName() + " found");
        }
        return allocationOPT.get().getResourceContainer_AllocationContext();
    }

    protected abstract ResourceContainerHandler getLocalResourceHandler();

    protected abstract ResourceContainerHandler getRemoteResourceHandler();

    @Override
    public void calculateAssemblyContextToAssemblyContextPropagation() {
        final var criticalAssembly = this.attackDAG.getRootNode().getContent().getContainedAssembly();
        final var criticalElement = toPCMElement(this.modelStorage, criticalAssembly);

        final var selectedNode = this.attackDAG.getSelectedNode();
        final var selectedComponent = selectedNode.getContent().getContainedAssembly();
        var sourceComponents = getConnectedComponents(
                selectedComponent)/*
                                   * .stream() .filter(e ->
                                   * !CacheCompromised.instance().compromised(e)).collect(Collectors.toList())
                                   */; // TODO
        final var handler = getAssemblyHandler();
        boolean isNotCompromisedBefore = !isCompromised(selectedComponent);
        if (isNotCompromisedBefore) {
            handler.attackAssemblyContext(Arrays.asList(selectedComponent), this.changes, selectedComponent);
        }

        if (isNotCompromisedBefore && isCompromised(selectedComponent)) {
            this.handleSeff(selectedComponent);
            compromise(selectedNode);
        }

        isNotCompromisedBefore = !isCompromised(selectedComponent);
        for (final var sourceComponent : sourceComponents) {
            // continue building the DAG
            final var childNode = selectedNode.addChild(new AttackStatusDescriptorNodeContent(sourceComponent));

            // TODO do not allow circles!!
            final var childComponent = childNode.getContent().getContainedAssembly();
            handler.attackAssemblyContext(Arrays.asList(selectedComponent), this.changes, childComponent);
            if (isNotCompromisedBefore && isCompromised(selectedComponent)) {
                this.handleSeff(childComponent);
                compromise(selectedNode);
            }
            
            // select the child node and recursively call the propagation call
            this.attackDAG.setSelectedNode(childNode);
            this.index++;
            this.calculateAssemblyContextToAssemblyContextPropagation();
            this.index--;
            this.attackDAG.setSelectedNode(selectedNode);
        }
    }
    
    private void compromise(final Node<AttackStatusDescriptorNodeContent> selectedNode) {
        selectedNode.getContent().setCompromised(true);
        this.changes.setChanged(true);
        generateAllFoundAttackPaths(this.attackDAG.getRootNode());
    }

    private static final boolean isCompromised(final Entity entity) {
        return CacheCompromised.instance().compromised(entity);
    }

    // TODO: these methods need to be somewhere else to be more reusable!
    private List<List<AttackStatusDescriptorNodeContent>> generateAllFoundAttackPaths(
            final Node<AttackStatusDescriptorNodeContent> root) { // TODO also partial paths?
        List<List<AttackStatusDescriptorNodeContent>> allPaths = new ArrayList<>();
        final var rootContent = root.getContent();
        if (rootContent.isCompromised()) {
            final var childrenOfRoot = root.getChildNodes();
            for (final var childNode : childrenOfRoot) {
                allPaths.addAll(generateAllFoundAttackPaths(childNode));
            }

            if (allPaths.isEmpty()) {
                allPaths.add(new ArrayList<>(Arrays.asList(rootContent)));
            } else {
                allPaths.forEach(p -> p.add(rootContent));
            }
            // only at the end of the recursion create the actual output attack paths
            if (root.equals(this.attackDAG.getRootNode())) {
                allPaths = allPaths.stream().distinct().collect(Collectors.toList());
                for (final var path : allPaths) {
                    final var criticalElement = root.getContent().getContainedAssembly();
                    convertToAttackPath(this.modelStorage, path, toPCMElement(this.modelStorage, criticalElement));
                }
            }
        }
        return allPaths;
    }

    private void convertToAttackPath(final BlackboardWrapper board,
            final List<AttackStatusDescriptorNodeContent> selectedPath, final PCMElement criticalPCMElement) {
        if (!selectedPath.isEmpty()) {
            final AttackPath path = AttackerFactory.eINSTANCE.createAttackPath();
            path.setCriticalElement(criticalPCMElement);

            for (final var nodeContent : selectedPath) {
                if (nodeContent.isCompromised()) {
                    final AssemblyContext assembly = nodeContent.getContainedAssembly(); // TODO more general
                    final PCMElement element = toPCMElement(board, assembly);

                    // TODO call method defined in sub-class for vuln. or something similar
                    final var systemIntegration = board.getVulnerabilitySpecification().getVulnerabilities().stream()
                            .filter(getElementIdEqualityPredicate(assembly)).findAny().orElse(null);
                    if (systemIntegration != null && !contains(path, systemIntegration)) {
                        systemIntegration.setPcmelement(element);
                        path.getPath().add(systemIntegration);
                    }
                } else {
                    break; // TODO: later maybe adapt for paths with gaps
                }
            }

            final boolean isPathAlreadyThere = this.attackDAG.getAlreadyFoundPaths().contains(selectedPath);
            if (!isPathAlreadyThere) {
                this.changes.getAttackpaths().add(path);
                this.attackDAG.addAlreadyFoundPath(selectedPath);
            }
        }
    }

    private static boolean contains(AttackPath path, SystemIntegration systemIntegration) {
        if (path != null && systemIntegration != null) {
            return path.getPath().contains(systemIntegration); // TODO does this work like this?
        }
        return false;
    }

    private static PCMElement toPCMElement(final BlackboardWrapper board, final AssemblyContext assembly) {
        final var container = board.getVulnerabilitySpecification().getVulnerabilities();
        if (container.stream().anyMatch(getElementIdEqualityPredicate(assembly))) {
            final var sysIntegration = container.stream().filter(getElementIdEqualityPredicate(assembly)).findAny()
                    .orElse(null);
            return sysIntegration.getPcmelement();
        }
        final var pcmElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        pcmElement.setAssemblycontext(assembly);
        final var sysIntegration = PcmIntegrationFactory.eINSTANCE.createRoleSystemIntegration(); // TODO maybe use
                                                                                                  // other system
                                                                                                  // integration
        container.add(sysIntegration);
        return pcmElement;
    }

    private static Predicate<SystemIntegration> getElementIdEqualityPredicate(final Entity entity) {
        return s -> {
            final Set<String> ids = new HashSet<>();
            final var pcmElement = s.getPcmelement();
            if (pcmElement != null && pcmElement.getAssemblycontext() != null)
                ids.add(pcmElement.getAssemblycontext().getId());
            // TODO adapt for other entity types as well and also check for null before!
            return ids.contains(entity.getId());
        };
    }

    @Override
    public void calculateAssemblyContextToGlobalAssemblyContextPropagation() {
        //TODO adapt
        
        final var listCompromisedContexts = getCompromisedAssemblyContexts().stream().filter(this::isGlobalElement)
                .collect(Collectors.toList());

        for (var component : listCompromisedContexts) {
            var resourceContainer = getResourceContainer(component);
            var connectedContainers = getConnectedResourceContainers(resourceContainer);
            var reachableAssemblies = CollectionHelper.getAssemblyContext(connectedContainers,
                    this.modelStorage.getAllocation());
            reachableAssemblies.addAll(
                    CollectionHelper.getAssemblyContext(List.of(resourceContainer), this.modelStorage.getAllocation()));
            final var handler = getAssemblyHandler();
            reachableAssemblies = CollectionHelper.removeDuplicates(reachableAssemblies).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            handler.attackAssemblyContext(reachableAssemblies, this.changes, component);

            var listServices = CollectionHelper.getProvidedRestrictions(reachableAssemblies).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            handleSeff(this.changes, listServices, component);
        }

    }

    private boolean isGlobalElement(AssemblyContext assemblyContext) {
        return this.modelStorage.getVulnerabilitySpecification().getVulnerabilities().stream().filter(
                systemElement -> EcoreUtil.equals(systemElement.getPcmelement().getAssemblycontext(), assemblyContext))
                .noneMatch(NonGlobalCommunication.class::isInstance);
    }

    private List<AssemblyContext> getConnectedComponents(final AssemblyContext component) {
        final var system = this.modelStorage.getAssembly();
        final var sourceConnectors = getSourcedConnectors(component, system);

        final var sourceComponents = sourceConnectors.stream()
                .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector)
                .filter(e -> !EcoreUtil.equals(e, component)).distinct() // TODO geht das so?
                .collect(Collectors.toList());
        /*
         * TODO remove v (s.u.) final var sourceComponents = sourceConnectors.stream()
         * .map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector)
         * .filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList());
         * 
         * sourceComponents .addAll(sourceConnectors.stream().map(AssemblyConnector::
         * getRequiringAssemblyContext_AssemblyConnector) .filter(e ->
         * !EcoreUtil.equals(e, component)).collect(Collectors.toList()));
         */
        return sourceComponents;
    }

    private List<AssemblyConnector> getSourcedConnectors(final AssemblyContext component, final System system) {
        return system.getConnectors__ComposedStructure().stream().filter(AssemblyConnector.class::isInstance)
                .map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
                /*
                 * || EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(),
                 * component)
                 */) // TODO providing too?
                .collect(Collectors.toList());
    }

    protected abstract AssemblyContextHandler getAssemblyHandler();

    @Override
    public void calculateAssemblyContextToLinkingResourcePropagation() {
        //TODO adapt
        
        final var listCompromisedAssemblyContexts = getCompromisedAssemblyContexts();

        for (final var component : listCompromisedAssemblyContexts) {
            final var resource = getResourceContainer(component);
            final var reachableLinkingResources = getLinkingResource(resource).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            final var handler = getLinkingHandler();
            handler.attackLinkingResource(reachableLinkingResources, this.changes, component);
        }
    }

    protected abstract LinkingResourceHandler getLinkingHandler();

}
