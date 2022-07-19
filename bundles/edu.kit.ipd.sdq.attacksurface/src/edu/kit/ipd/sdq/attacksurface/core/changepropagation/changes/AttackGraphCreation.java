package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.List;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.PCMConnectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.AttackVectorHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.CredentialSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import com.google.common.graph.ImmutableNetwork;
import com.google.common.graph.MutableNetwork;
import com.google.common.graph.NetworkBuilder;

import edu.kit.ipd.sdq.attacksurface.graph.AttackEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.LinkingPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;

public class AttackGraphCreation
        implements AssemblyContextPropagation, LinkingPropagation, ResourceContainerPropagation {

    private MutableNetwork<AttackNodeContent, AttackEdge> graph;
    private BlackboardWrapper modelStorage;

    public AttackGraphCreation(BlackboardWrapper modelStorage) {
        this.graph = NetworkBuilder.directed().allowsParallelEdges(true).build();
        this.modelStorage = modelStorage;
    }

    private void createEdgeVulnerability(Entity rootEntity, Entity connectedEntity, List<Vulnerability> vulnerabilities,
            AttackVector vector) {
        for (var vulnerability : vulnerabilities) {
            if (!AttackVectorHelper.isIncluded(vector, vulnerability.getAttackVector())) {
                continue;
            }
            var node1 = new AttackNodeContent(rootEntity);
            var node2 = new AttackNodeContent(connectedEntity);
            var edge = new AttackEdge(rootEntity, connectedEntity, vulnerability, null);

            this.graph.addEdge(node1, node2, edge);

        }
    }

    private void createEdgeCredentials(Entity rootEntity, Entity connectedEntity, BlackboardWrapper modelStorage) {

        var credentials = getCredentialIntegrations(connectedEntity);

        var node1 = new AttackNodeContent(rootEntity);
        var node2 = new AttackNodeContent(connectedEntity);
        var edge = new AttackEdge(rootEntity, connectedEntity, null, credentials);

        this.graph.addEdge(node1, node2, edge);

    }

    private void createEdgeImplicit(Entity rootEntity, Entity connectedEntity, BlackboardWrapper modelStorage) {

        var credentials = getCredentialIntegrations(connectedEntity);

        var node1 = new AttackNodeContent(rootEntity);
        var node2 = new AttackNodeContent(connectedEntity);
        var edge = new AttackEdge(rootEntity, connectedEntity, null, credentials, true, AttackVector.LOCAL);

        this.graph.addEdge(node1, node2, edge);

    }

    private List<? extends UsageSpecification> getCredentialIntegrations(Entity target) {
        return this.modelStorage.getVulnerabilitySpecification().getVulnerabilities().stream()
                .filter(PCMElementType.typeOf(target).getElementEqualityPredicate(target))
                .filter(CredentialSystemIntegration.class::isInstance).map(CredentialSystemIntegration.class::cast)
                .map(CredentialSystemIntegration::getCredential).collect(Collectors.toList());
    }

    @Override
    public void calculateAssemblyContextToRemoteResourcePropagation() {
        for (var component : this.modelStorage.getAssembly().getAssemblyContexts__ComposedStructure()) {
            var resource = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());


            if (CollectionHelper.isGlobalCommunication(component,
                    this.modelStorage.getVulnerabilitySpecification().getVulnerabilities())) {
                // find directly connected Resources
                // only GlobalCommunication since non Global can't connect
                var connectedResources = PCMConnectionHelper.getConnectedResourceContainers(resource,
                        this.modelStorage.getResourceEnvironment());
                for (var connectedResource : connectedResources) {
                    var vulnerabilities = VulnerabilityHelper
                            .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), connectedResource);
                    createEdgeVulnerability(component, connectedResource, vulnerabilities,
                            AttackVector.ADJACENT_NETWORK);
                    createEdgeCredentials(component, connectedResource, this.modelStorage);
                }
            }

            // find indirectly reachable resources
            var assemblies = PCMConnectionHelper.getConnectectedAssemblies(this.modelStorage.getAssembly(), component);
            var reachAbleResources = assemblies.stream()
                    .map(c -> PCMConnectionHelper.getResourceContainer(c, this.modelStorage.getAllocation())).toList();
            for (var connectedResource : reachAbleResources) {
                // add potential filtering to remove duplicates
//                if (connectedResources.stream().anyMatch(e -> e.getId().equals(connectedResource.getId()))) {
//                    continue;
//                }
                var vulnerabilities = VulnerabilityHelper
                        .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), connectedResource);
                createEdgeVulnerability(component, connectedResource, vulnerabilities,
                        isConncected(connectedResource, resource));
                createEdgeCredentials(component, connectedResource, this.modelStorage);
            }

        }

    }

    @Override
    public void calculateAssemblyContextToLocalResourcePropagation() {
        for (var component : this.modelStorage.getAssembly().getAssemblyContexts__ComposedStructure()) {
            var resource = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());

            var vulnerabilities = VulnerabilityHelper
                    .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), resource);
            createEdgeVulnerability(component, resource, vulnerabilities, AttackVector.LOCAL);
            createEdgeCredentials(component, resource, this.modelStorage);
        }

    }

    @Override
    public void calculateAssemblyContextToLinkingResourcePropagation() {
        for (var component : this.modelStorage.getAssembly().getAssemblyContexts__ComposedStructure()) {
            var resource = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());
            var reachableLinking = PCMConnectionHelper.getLinkingResource(resource,
                    this.modelStorage.getResourceEnvironment());

            createEdgeLinkingResources(component, reachableLinking);

        }

    }

    private void createEdgeLinkingResources(Entity component, List<LinkingResource> reachableLinking) {
        for (var linking : reachableLinking) {
            var vulnerabilities = VulnerabilityHelper
                    .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), linking);
            createEdgeVulnerability(component, linking, vulnerabilities, AttackVector.NETWORK);
            createEdgeCredentials(component, linking, this.modelStorage);
        }
    }

    @Override
    public void calculateAssemblyContextToGlobalAssemblyContextPropagation() {
        var globalComponents = this.modelStorage.getAssembly().getAssemblyContexts__ComposedStructure().stream()
                .filter(assembly -> CollectionHelper.isGlobalCommunication(assembly,
                        this.modelStorage.getVulnerabilitySpecification().getVulnerabilities()))
                .toList();

        for (var component : globalComponents) {
            var resource = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());
            var reachableResource = PCMConnectionHelper.getConnectedResourceContainers(resource,
                    this.modelStorage.getResourceEnvironment());

            var reachableComponents = CollectionHelper.getAssemblyContext(reachableResource,
                    this.modelStorage.getAllocation());

            createGraphEdgesComponents(component, reachableComponents);

        }

    }

    private void createGraphEdgesComponents(Entity rootElement,
            List<AssemblyContext> targetComponents) {
        for (var targetComponent : targetComponents) {

            var vulnerabilities = VulnerabilityHelper
                    .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), targetComponent);
            createEdgeVulnerability(rootElement, targetComponent, vulnerabilities, AttackVector.ADJACENT_NETWORK);
            createEdgeCredentials(rootElement, targetComponent, this.modelStorage);
        }
    }

    @Override
    public void calculateAssemblyContextToAssemblyContextPropagation() {
        for (var component : this.modelStorage.getAssembly().getAssemblyContexts__ComposedStructure()) {

            var connectedComponents = PCMConnectionHelper.getConnectectedAssemblies(this.modelStorage.getAssembly(),
                    component);
            for (var connectedComponent : connectedComponents) {
                var vulnerabilities = VulnerabilityHelper
                        .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), connectedComponent);

                var resource1 = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());
                var resource2 = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());

                createEdgeVulnerability(component, connectedComponent, vulnerabilities,
                        isConncected(resource1, resource2));
                createEdgeCredentials(component, connectedComponent, this.modelStorage);
            }
        }
    }

    private AttackVector isConncected(ResourceContainer resource1, ResourceContainer resource2) {
        var linking1 = PCMConnectionHelper.getLinkingResource(resource1, this.modelStorage.getResourceEnvironment());
        var linking2 = PCMConnectionHelper.getLinkingResource(resource2, this.modelStorage.getResourceEnvironment());

        for (var linking : linking1) {
            if (linking2.stream().anyMatch(e -> e.getId().equals(linking.getId()))) {
                return AttackVector.ADJACENT_NETWORK;
            }
        }
        return AttackVector.NETWORK;
    }

    @Override
    public void calculateLinkingResourceToResourcePropagation() {
        for (var linking : this.modelStorage.getResourceEnvironment().getLinkingResources__ResourceEnvironment()) {
            var resources = linking.getConnectedResourceContainers_LinkingResource();

            createEdgeResourceContainer(linking, resources);

        }

    }

    private void createEdgeResourceContainer(Entity linking, List<ResourceContainer> resources) {
        for (var resource : resources) {

            var vulnerabilities = VulnerabilityHelper
                    .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), resource);
            createEdgeVulnerability(linking, resource, vulnerabilities, AttackVector.ADJACENT_NETWORK);
            createEdgeCredentials(linking, resource, this.modelStorage);
        }
    }

    @Override
    public void calculateLinkingResourceToAssemblyContextPropagation() {
        for (var linking : this.modelStorage.getResourceEnvironment().getLinkingResources__ResourceEnvironment()) {
            var resources = linking.getConnectedResourceContainers_LinkingResource();
            var components = CollectionHelper.getAssemblyContext(resources, this.modelStorage.getAllocation());
            createGraphEdgesComponents(linking, components);

        }

    }

    @Override
    public void calculateResourceContainerToRemoteAssemblyContextPropagation() {
        for (var resource : this.modelStorage.getResourceEnvironment().getResourceContainer_ResourceEnvironment()) {
            var reachableResources = PCMConnectionHelper.getConnectedResourceContainers(resource,
                    this.modelStorage.getResourceEnvironment());
            var components = CollectionHelper.getAssemblyContext(reachableResources, this.modelStorage.getAllocation());
            components = components.stream().filter(e -> !CollectionHelper.isGlobalCommunication(e,
                    this.modelStorage.getVulnerabilitySpecification().getVulnerabilities())).toList();
            createGraphEdgesComponents(resource, components);
        }

    }

    @Override
    public void calculateResourceContainerToLocalAssemblyContextPropagation() {
        for(var resource: this.modelStorage.getResourceEnvironment().getResourceContainer_ResourceEnvironment()) {
            var targetComponents = CollectionHelper.getAssemblyContext(List.of(resource), this.modelStorage.getAllocation());
            for (var target : targetComponents) {
                createEdgeImplicit(resource, target, this.modelStorage);
            }
        }

    }

    @Override
    public void calculateResourceContainerToResourcePropagation() {
        for (var resource : this.modelStorage.getResourceEnvironment().getResourceContainer_ResourceEnvironment()) {
            var resources = PCMConnectionHelper.getConnectedResourceContainers(resource,
                    this.modelStorage.getResourceEnvironment());
            createEdgeResourceContainer(resource, resources);

        }

    }

    @Override
    public void calculateResourceContainerToLinkingResourcePropagation() {
        for (var resource : this.modelStorage.getResourceEnvironment().getResourceContainer_ResourceEnvironment()) {
            var linkings = PCMConnectionHelper.getLinkingResource(resource, this.modelStorage.getResourceEnvironment());

            createEdgeLinkingResources(resource, linkings);
        }

    }

    public ImmutableNetwork<AttackNodeContent, AttackEdge> getGraph() {
        return NetworkBuilder.from(this.graph).immutable().build();
    }

}
