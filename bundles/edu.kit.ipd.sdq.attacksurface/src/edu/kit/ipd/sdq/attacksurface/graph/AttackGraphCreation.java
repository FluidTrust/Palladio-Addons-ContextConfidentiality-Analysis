package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.PCMConnectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.AttackVectorHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.policy.AllOf;
import org.palladiosimulator.pcm.confidentiality.context.policy.Apply;
import org.palladiosimulator.pcm.confidentiality.context.policy.Expression;
import org.palladiosimulator.pcm.confidentiality.context.policy.Operations;
import org.palladiosimulator.pcm.confidentiality.context.policy.Policy;
import org.palladiosimulator.pcm.confidentiality.context.policy.PolicySet;
import org.palladiosimulator.pcm.confidentiality.context.policy.Rule;
import org.palladiosimulator.pcm.confidentiality.context.policy.SimpleAttributeCondition;
import org.palladiosimulator.pcm.confidentiality.context.policy.util.PolicySwitch;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.EntityMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.MethodMatch;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import com.att.research.xacmlatt.pdp.policy.Match;
import com.google.common.collect.Streams;
import com.google.common.graph.ImmutableNetwork;
import com.google.common.graph.MutableNetwork;
import com.google.common.graph.NetworkBuilder;

import edu.kit.ipd.sdq.attacksurface.core.AttackHandlingHelper;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.LinkingPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;

/**
 * Class for creating an attack graph. It uses <a href="https://github.com/google/guava">Google
 * Guava</a> as internal graph representation
 *
 * It iteratively calculates for each architectural elements the neighbouring elements and adds an
 * edge if the neighbours are connected by an exploitable connection. For edges it uses the
 * {@link AttackEdge} and the architectural elements are represented in the graph as
 * {@link ArchitectureNode}
 *
 * @author majuwa
 *
 */
public class AttackGraphCreation
        implements AssemblyContextPropagation, LinkingPropagation, ResourceContainerPropagation {

    private static final Logger LOGGER = Logger.getLogger(AttackGraphCreation.class.getName());
    private volatile MutableNetwork<ArchitectureNode, AttackEdge> graph;
    private BlackboardWrapper modelStorage;
    private PolicySet policies;

    public AttackGraphCreation(BlackboardWrapper modelStorage) {
        this.graph = NetworkBuilder.directed().allowsParallelEdges(true).build();
        this.modelStorage = modelStorage;
        if (modelStorage.getSpecification().eContainer() instanceof ConfidentialAccessSpecification policies) {
            this.policies = policies.getPolicyset();

        } else {
            throw new IllegalArgumentException("No AccessControl description found");
        }
        if (!isValidAccessControll()) {
            throw new IllegalStateException("Access control files contains unsupported elements");
        }
    }

    private boolean isValidAccessControll() {
        if (this.policies == null) {
            LOGGER.log(Level.WARNING, "No Policiy found");
            return true;
        }

        var checkEntityMatch = this.policies.eContents().stream().filter(Match.class::isInstance)
                .allMatch(this::isCorrectMatchType);
        if (!checkEntityMatch) {
            LOGGER.log(Level.SEVERE, "Access Control contains non supported Match Elements");
        }
        var checkConditions = this.policies.eContents().stream().filter(Expression.class::isInstance).allMatch(e -> {
            if (e instanceof Apply apply) {
                return Objects.equals(apply.getOperation(), Operations.AND);
            } else if (e instanceof SimpleAttributeCondition) {
                return true;
            }
            return false;
        });
        if (!checkConditions) {
            LOGGER.log(Level.SEVERE, "Access Control contains non supported Expression elements");
        }

        return checkEntityMatch && checkConditions;
    }

    private boolean isCorrectMatchType(EObject match) {
        return match instanceof EntityMatch || match instanceof MethodMatch;
    }

    private void createEdgeVulnerability(Entity rootEntity, Entity connectedEntity, List<Vulnerability> vulnerabilities,
            AttackVector vector) {
        for (var vulnerability : vulnerabilities) {
            if (!AttackVectorHelper.isIncluded(vector, vulnerability.getAttackVector())) {
                continue;
            }
            if (!AttackHandlingHelper.notFilteredVulnerability(this.modelStorage, vulnerability)) {
                continue;
            }
            var node1 = new ArchitectureNode(rootEntity);
            var node2 = new ArchitectureNode(connectedEntity);
            var edge = new AttackEdge(rootEntity, connectedEntity, vulnerability, null);

            insertEdge(node1, node2, edge);

        }
    }

    private void createEdgeCredentials(Entity rootEntity, Entity connectedEntity, BlackboardWrapper modelStorage) {

        var credentials = getCredentialIntegrations(connectedEntity);

        if (!credentials.isEmpty()) {
            var node1 = new ArchitectureNode(rootEntity);
            var node2 = new ArchitectureNode(connectedEntity);
            for (var credentialEdge : credentials) {
                var edge = new AttackEdge(rootEntity, connectedEntity, null, credentialEdge);

                insertEdge(node1, node2, edge);
            }
        }

    }

    private synchronized void insertEdge(ArchitectureNode node1, ArchitectureNode node2, AttackEdge edge) {
        this.graph.addEdge(node1, node2, edge);
    }

    private void createEdgeImplicit(Entity rootEntity, Entity connectedEntity, BlackboardWrapper modelStorage) {

//        var credentials = getCredentialIntegrations(connectedEntity);

        var node1 = new ArchitectureNode(rootEntity);
        var node2 = new ArchitectureNode(connectedEntity);
//        if (credentials.isEmpty()) {
            var edge = new AttackEdge(rootEntity, connectedEntity, null, List.of(), true, AttackVector.LOCAL);

            insertEdge(node1, node2, edge);
//        } else {
//            for (var credential : credentials) {
//                var edge = new AttackEdge(rootEntity, connectedEntity, null, credential, true, AttackVector.LOCAL);
//
//                insertEdge(node1, node2, edge);
//            }
//        }

    }

    private List<List<UsageSpecification>> getCredentialIntegrations(Entity target) {

        var matches = Streams.stream(this.policies.eAllContents()).filter(AllOf.class::isInstance)
                .map(AllOf.class::cast)
                .filter(e -> e.getMatch().size() == 1).flatMap(e -> e.getMatch().stream()).filter(EntityMatch.class::isInstance).map(EntityMatch.class::cast).filter(e-> e.getEntity().getId().equals(target.getId())).toList();




        var switchExpression = new PolicySwitch<List<UsageSpecification>>() {
            @Override
            public List<UsageSpecification> caseSimpleAttributeCondition(SimpleAttributeCondition condition) {
                return List.of(condition.getAttribute());
            }

            @Override
            public List<UsageSpecification> caseApply(Apply apply) {
                return apply.getParameters().stream().flatMap(e -> this.doSwitch(e).stream()).toList();
            }
        };

        var policySwitch = new PolicySwitch<List<List<UsageSpecification>>>() {

            @Override
            public List<List<UsageSpecification>> casePolicySet(PolicySet object) {
                var policyStream = object.getPolicy().stream().flatMap(e -> this.doSwitch(e).stream());
                var policySetStream = object.getPolicyset().stream().flatMap(e -> this.doSwitch(e).stream());
                return Stream.concat(policyStream, policySetStream).toList();
            }

            @Override
            public List<List<UsageSpecification>> casePolicy(Policy object) {

                return object.getRule().stream().flatMap(e -> this.doSwitch(e).stream()).toList();
            }

            @Override
            public List<List<UsageSpecification>> caseRule(Rule rule) {
                return List.of(switchExpression.doSwitch(rule.getCondition()));
            }

        };

        return matches.stream().map(EObject::eContainer).map(EObject::eContainer)
                .flatMap(e -> policySwitch.doSwitch(e).stream()).toList();

//        return this.modelStorage.getVulnerabilitySpecification().getVulnerabilities().stream()
//                .filter(PCMElementType.typeOf(target).getElementEqualityPredicate(target))
//                .filter(CredentialSystemIntegration.class::isInstance).map(CredentialSystemIntegration.class::cast)
//                .map(CredentialSystemIntegration::getCredential).collect(Collectors.toList());
    }

    @Override
    public void calculateAssemblyContextToRemoteResourcePropagation() {
        this.modelStorage.getAssembly().getAssemblyContexts__ComposedStructure().parallelStream().forEach(component -> {
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

        });

    }

    @Override
    public void calculateAssemblyContextToLocalResourcePropagation() {
        this.modelStorage.getAssembly().getAssemblyContexts__ComposedStructure().parallelStream().forEach(component -> {
            var resource = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());

            var vulnerabilities = VulnerabilityHelper
                    .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), resource);
            createEdgeVulnerability(component, resource, vulnerabilities, AttackVector.LOCAL);
            createEdgeCredentials(component, resource, this.modelStorage);
        });

    }

    @Override
    public void calculateAssemblyContextToLinkingResourcePropagation() {
        this.modelStorage.getAssembly().getAssemblyContexts__ComposedStructure().parallelStream().forEach(component -> {
            var resource = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());
            var reachableLinking = PCMConnectionHelper.getLinkingResource(resource,
                    this.modelStorage.getResourceEnvironment());

            createEdgeLinkingResources(component, reachableLinking);

        });

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
        var globalComponents = this.modelStorage.getAssembly().getAssemblyContexts__ComposedStructure().parallelStream()
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

    private void createGraphEdgesComponents(Entity rootElement, List<AssemblyContext> targetComponents) {
        for (var targetComponent : targetComponents) {

            var vulnerabilities = VulnerabilityHelper
                    .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), targetComponent);
            createEdgeVulnerability(rootElement, targetComponent, vulnerabilities, AttackVector.ADJACENT_NETWORK);
            createEdgeCredentials(rootElement, targetComponent, this.modelStorage);
        }
    }

    @Override
    public void calculateAssemblyContextToAssemblyContextPropagation() {
        this.modelStorage.getAssembly().getAssemblyContexts__ComposedStructure().parallelStream().forEach(component -> {

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
        });
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
        this.modelStorage.getResourceEnvironment().getLinkingResources__ResourceEnvironment().parallelStream()
                .forEach(linking -> {
            var resources = linking.getConnectedResourceContainers_LinkingResource();

            createEdgeResourceContainer(linking, resources);

                });

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
        this.modelStorage.getResourceEnvironment().getLinkingResources__ResourceEnvironment().parallelStream()
                .forEach(linking -> {
            var resources = linking.getConnectedResourceContainers_LinkingResource();
            var components = CollectionHelper.getAssemblyContext(resources, this.modelStorage.getAllocation());
            createGraphEdgesComponents(linking, components);

                });

    }

    @Override
    public void calculateResourceContainerToRemoteAssemblyContextPropagation() {
        this.modelStorage.getResourceEnvironment().getResourceContainer_ResourceEnvironment().parallelStream()
                .forEach(resource -> {
            var reachableResources = PCMConnectionHelper.getConnectedResourceContainers(resource,
                    this.modelStorage.getResourceEnvironment());
            var components = CollectionHelper.getAssemblyContext(reachableResources, this.modelStorage.getAllocation());
            components = components.stream().filter(e -> !CollectionHelper.isGlobalCommunication(e,
                    this.modelStorage.getVulnerabilitySpecification().getVulnerabilities())).toList();
            createGraphEdgesComponents(resource, components);
                });

    }

    @Override
    public void calculateResourceContainerToLocalAssemblyContextPropagation() {
        this.modelStorage.getResourceEnvironment().getResourceContainer_ResourceEnvironment().parallelStream()
                .forEach(resource -> {
            var targetComponents = CollectionHelper.getAssemblyContext(List.of(resource),
                    this.modelStorage.getAllocation());
            for (var target : targetComponents) {
                createEdgeImplicit(resource, target, this.modelStorage);
            }
                });

    }

    @Override
    public void calculateResourceContainerToResourcePropagation() {

//        this.modelStorage.getResourceEnvironment().getResourceContainer_ResourceEnvironment().parallelStream()
//                .forEach(resource -> {
//            var resources = PCMConnectionHelper.getConnectedResourceContainers(resource,
//                    this.modelStorage.getResourceEnvironment());
//            createEdgeResourceContainer(resource, resources);
//                });
        this.modelStorage.getResourceEnvironment().getResourceContainer_ResourceEnvironment().parallelStream()
                .forEach(resource -> {

            var resources = PCMConnectionHelper.getConnectedResourceContainers(resource,
                    this.modelStorage.getResourceEnvironment());
            createEdgeResourceContainer(resource, resources);

                });

    }

    @Override
    public void calculateResourceContainerToLinkingResourcePropagation() {

//        this.modelStorage.getResourceEnvironment().getResourceContainer_ResourceEnvironment().parallelStream()
//                .forEach(resource -> {
//            var linkings = PCMConnectionHelper.getLinkingResource(resource, this.modelStorage.getResourceEnvironment());
//
//            createEdgeLinkingResources(resource, linkings);
//                });
        this.modelStorage.getResourceEnvironment().getResourceContainer_ResourceEnvironment().parallelStream()
                .forEach(resource -> {
            var linkings = PCMConnectionHelper.getLinkingResource(resource, this.modelStorage.getResourceEnvironment());

            createEdgeLinkingResources(resource, linkings);
                });


    }

    /**
     * Calculates the attack graph and stores it internally.
     */
    public void createGraph() {
        // calculate the attack graph in parallel
        var future = CompletableFuture.allOf(
                CompletableFuture.runAsync(this::calculateAssemblyContextToAssemblyContextPropagation),

                CompletableFuture.runAsync(this::calculateAssemblyContextToAssemblyContextPropagation),
                CompletableFuture.runAsync(this::calculateAssemblyContextToGlobalAssemblyContextPropagation),
                CompletableFuture.runAsync(this::calculateAssemblyContextToLinkingResourcePropagation),
                CompletableFuture.runAsync(this::calculateAssemblyContextToLocalResourcePropagation),
                CompletableFuture.runAsync(this::calculateAssemblyContextToRemoteResourcePropagation),

                CompletableFuture.runAsync(this::calculateLinkingResourceToAssemblyContextPropagation),
                CompletableFuture.runAsync(this::calculateLinkingResourceToResourcePropagation),

                CompletableFuture.runAsync(this::calculateResourceContainerToLinkingResourcePropagation),
                CompletableFuture.runAsync(this::calculateResourceContainerToLocalAssemblyContextPropagation),
                CompletableFuture.runAsync(this::calculateResourceContainerToRemoteAssemblyContextPropagation),
                CompletableFuture.runAsync(this::calculateResourceContainerToResourcePropagation));
        try {
            future.get();
        } catch (ExecutionException e) {
            LOGGER.log(Level.SEVERE, "Error during graph creation", e);
            Thread.currentThread().interrupt();
            throw new IllegalStateException("IllegalState durin graph creation", e);
        } catch (InterruptedException e) {
            LOGGER.log(Level.SEVERE, "Error during graph creation", e);
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Creates an immutable copy of the internal attack graph and returns it
     *
     * @return {@link ImmutableNetwork} copy of internal graph
     */
    public ImmutableNetwork<ArchitectureNode, AttackEdge> getGraph() {
        return ImmutableNetwork.copyOf(this.graph);
    }

}
