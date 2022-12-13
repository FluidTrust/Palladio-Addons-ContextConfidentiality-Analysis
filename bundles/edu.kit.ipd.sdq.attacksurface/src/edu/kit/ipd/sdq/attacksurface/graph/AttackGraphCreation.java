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
    private final BlackboardWrapper modelStorage;
    private PolicySet policies;

    public AttackGraphCreation(final BlackboardWrapper modelStorage) {
        this.graph = NetworkBuilder.directed()
            .allowsParallelEdges(true)
            .build();
        this.modelStorage = modelStorage;
        if (modelStorage.getSpecification()
            .eContainer() instanceof final ConfidentialAccessSpecification policies) {
            this.policies = policies.getPolicyset();

        } else {
            throw new IllegalArgumentException("No AccessControl description found");
        }
        if (!this.isValidAccessControll()) {
            throw new IllegalStateException("Access control files contains unsupported elements");
        }
    }

    private boolean isValidAccessControll() {
        if (this.policies == null) {
            LOGGER.log(Level.WARNING, "No Policiy found");
            return true;
        }

        final var checkEntityMatch = this.policies.eContents()
            .stream()
            .filter(Match.class::isInstance)
            .allMatch(this::isCorrectMatchType);
        if (!checkEntityMatch) {
            LOGGER.log(Level.SEVERE, "Access Control contains non supported Match Elements");
        }
        final var checkConditions = this.policies.eContents()
            .stream()
            .filter(Expression.class::isInstance)
            .allMatch(e -> {
                if (e instanceof final Apply apply) {
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

    private boolean isCorrectMatchType(final EObject match) {
        return match instanceof EntityMatch || match instanceof MethodMatch;
    }

    private void createEdgeVulnerability(final Entity rootEntity, final Entity connectedEntity,
            final List<Vulnerability> vulnerabilities, final AttackVector vector) {
        for (final var vulnerability : vulnerabilities) {
            if (!AttackVectorHelper.isIncluded(vector, vulnerability.getAttackVector()) || !AttackHandlingHelper.notFilteredVulnerability(this.modelStorage, vulnerability)) {
                continue;
            }
            final var node1 = new ArchitectureNode(rootEntity);
            final var node2 = new ArchitectureNode(connectedEntity);
            final var edge = new AttackEdge(rootEntity, connectedEntity, vulnerability, null);

            this.insertEdge(node1, node2, edge);

        }
    }

    private void createEdgeCredentials(final Entity rootEntity, final Entity connectedEntity,
            final BlackboardWrapper modelStorage) {

        final var credentials = this.getCredentialIntegrations(connectedEntity);

        if (!credentials.isEmpty()) {
            final var node1 = new ArchitectureNode(rootEntity);
            final var node2 = new ArchitectureNode(connectedEntity);
            for (final var credentialEdge : credentials) {
                final var edge = new AttackEdge(rootEntity, connectedEntity, null, credentialEdge);

                this.insertEdge(node1, node2, edge);
            }
        }

    }

    private synchronized void insertEdge(final ArchitectureNode node1, final ArchitectureNode node2,
            final AttackEdge edge) {
        this.graph.addEdge(node1, node2, edge);
    }

    private void createEdgeImplicit(final Entity rootEntity, final Entity connectedEntity,
            final BlackboardWrapper modelStorage) {

//        var credentials = getCredentialIntegrations(connectedEntity);

        final var node1 = new ArchitectureNode(rootEntity);
        final var node2 = new ArchitectureNode(connectedEntity);
//        if (credentials.isEmpty()) {
        final var edge = new AttackEdge(rootEntity, connectedEntity, null, List.of(), true, AttackVector.LOCAL);

        this.insertEdge(node1, node2, edge);
//        } else {
//            for (var credential : credentials) {
//                var edge = new AttackEdge(rootEntity, connectedEntity, null, credential, true, AttackVector.LOCAL);
//
//                insertEdge(node1, node2, edge);
//            }
//        }

    }

    private List<List<UsageSpecification>> getCredentialIntegrations(final Entity target) {

        final var matches = Streams.stream(this.policies.eAllContents())
            .filter(AllOf.class::isInstance)
            .map(AllOf.class::cast)
            .filter(e -> e.getMatch()
                .size() == 1)
            .flatMap(e -> e.getMatch()
                .stream())
            .filter(EntityMatch.class::isInstance)
            .map(EntityMatch.class::cast)
            .filter(e -> e.getEntity()
                .getId()
                .equals(target.getId()))
            .toList();

        final var switchExpression = new PolicySwitch<List<UsageSpecification>>() {
            @Override
            public List<UsageSpecification> caseSimpleAttributeCondition(final SimpleAttributeCondition condition) {
                return List.of(condition.getAttribute());
            }

            @Override
            public List<UsageSpecification> caseApply(final Apply apply) {
                return apply.getParameters()
                    .stream()
                    .flatMap(e -> this.doSwitch(e)
                        .stream())
                    .toList();
            }
        };

        final var policySwitch = new PolicySwitch<List<List<UsageSpecification>>>() {

            @Override
            public List<List<UsageSpecification>> casePolicySet(final PolicySet object) {
                final var policyStream = object.getPolicy()
                    .stream()
                    .flatMap(e -> this.doSwitch(e)
                        .stream());
                final var policySetStream = object.getPolicyset()
                    .stream()
                    .flatMap(e -> this.doSwitch(e)
                        .stream());
                return Stream.concat(policyStream, policySetStream)
                    .toList();
            }

            @Override
            public List<List<UsageSpecification>> casePolicy(final Policy object) {

                return object.getRule()
                    .stream()
                    .flatMap(e -> this.doSwitch(e)
                        .stream())
                    .toList();
            }

            @Override
            public List<List<UsageSpecification>> caseRule(final Rule rule) {
                return List.of(switchExpression.doSwitch(rule.getCondition()));
            }

        };

        return matches.stream()
            .map(EObject::eContainer)
            .map(EObject::eContainer)
            .flatMap(e -> policySwitch.doSwitch(e)
                .stream())
            .toList();

//        return this.modelStorage.getVulnerabilitySpecification().getVulnerabilities().stream()
//                .filter(PCMElementType.typeOf(target).getElementEqualityPredicate(target))
//                .filter(CredentialSystemIntegration.class::isInstance).map(CredentialSystemIntegration.class::cast)
//                .map(CredentialSystemIntegration::getCredential).collect(Collectors.toList());
    }

    @Override
    public void calculateAssemblyContextToRemoteResourcePropagation() {
        this.modelStorage.getAssembly()
            .getAssemblyContexts__ComposedStructure()
            .parallelStream()
            .forEach(component -> {
                final var resource = PCMConnectionHelper.getResourceContainer(component,
                        this.modelStorage.getAllocation());

                if (CollectionHelper.isGlobalCommunication(component, this.modelStorage.getVulnerabilitySpecification()
                    .getVulnerabilities())) {
                    // find directly connected Resources
                    // only GlobalCommunication since non Global can't connect
                    final var connectedResources = PCMConnectionHelper.getConnectedResourceContainers(resource,
                            this.modelStorage.getResourceEnvironment());
                    for (final var connectedResource : connectedResources) {
                        final var vulnerabilities = VulnerabilityHelper
                            .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), connectedResource);
                        this.createEdgeVulnerability(component, connectedResource, vulnerabilities,
                                AttackVector.ADJACENT_NETWORK);
                        this.createEdgeCredentials(component, connectedResource, this.modelStorage);
                    }
                }

                // find indirectly reachable resources
                final var assemblies = PCMConnectionHelper.getConnectectedAssemblies(this.modelStorage.getAssembly(),
                        component);
                final var reachAbleResources = assemblies.stream()
                    .map(c -> PCMConnectionHelper.getResourceContainer(c, this.modelStorage.getAllocation()))
                    .toList();
                for (final var connectedResource : reachAbleResources) {
                    // add potential filtering to remove duplicates
//                if (connectedResources.stream().anyMatch(e -> e.getId().equals(connectedResource.getId()))) {
//                    continue;
//                }
                    final var vulnerabilities = VulnerabilityHelper
                        .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), connectedResource);
                    this.createEdgeVulnerability(component, connectedResource, vulnerabilities,
                            this.isConncected(connectedResource, resource));
                    this.createEdgeCredentials(component, connectedResource, this.modelStorage);
                }

            });

    }

    @Override
    public void calculateAssemblyContextToLocalResourcePropagation() {
        this.modelStorage.getAssembly()
            .getAssemblyContexts__ComposedStructure()
            .parallelStream()
            .forEach(component -> {
                final var resource = PCMConnectionHelper.getResourceContainer(component,
                        this.modelStorage.getAllocation());

                final var vulnerabilities = VulnerabilityHelper
                    .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), resource);
                this.createEdgeVulnerability(component, resource, vulnerabilities, AttackVector.LOCAL);
                this.createEdgeCredentials(component, resource, this.modelStorage);
            });

    }

    @Override
    public void calculateAssemblyContextToLinkingResourcePropagation() {
        this.modelStorage.getAssembly()
            .getAssemblyContexts__ComposedStructure()
            .parallelStream()
            .forEach(component -> {
                final var resource = PCMConnectionHelper.getResourceContainer(component,
                        this.modelStorage.getAllocation());
                final var reachableLinking = PCMConnectionHelper.getLinkingResource(resource,
                        this.modelStorage.getResourceEnvironment());

                this.createEdgeLinkingResources(component, reachableLinking);

            });

    }

    private void createEdgeLinkingResources(final Entity component, final List<LinkingResource> reachableLinking) {
        for (final var linking : reachableLinking) {
            final var vulnerabilities = VulnerabilityHelper
                .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), linking);
            this.createEdgeVulnerability(component, linking, vulnerabilities, AttackVector.NETWORK);
            this.createEdgeCredentials(component, linking, this.modelStorage);
        }
    }

    @Override
    public void calculateAssemblyContextToGlobalAssemblyContextPropagation() {
        final var globalComponents = this.modelStorage.getAssembly()
            .getAssemblyContexts__ComposedStructure()
            .parallelStream()
            .filter(assembly -> CollectionHelper.isGlobalCommunication(assembly,
                    this.modelStorage.getVulnerabilitySpecification()
                        .getVulnerabilities()))
            .toList();

        for (final var component : globalComponents) {
            final var resource = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());
            final var reachableResource = PCMConnectionHelper.getConnectedResourceContainers(resource,
                    this.modelStorage.getResourceEnvironment());

            final var reachableComponents = CollectionHelper.getAssemblyContext(reachableResource,
                    this.modelStorage.getAllocation());

            this.createGraphEdgesComponents(component, reachableComponents);

        }

    }

    private void createGraphEdgesComponents(final Entity rootElement, final List<AssemblyContext> targetComponents) {
        for (final var targetComponent : targetComponents) {

            final var vulnerabilities = VulnerabilityHelper
                .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), targetComponent);
            this.createEdgeVulnerability(rootElement, targetComponent, vulnerabilities, AttackVector.ADJACENT_NETWORK);
            this.createEdgeCredentials(rootElement, targetComponent, this.modelStorage);
        }
    }

    @Override
    public void calculateAssemblyContextToAssemblyContextPropagation() {
        this.modelStorage.getAssembly()
            .getAssemblyContexts__ComposedStructure()
            .parallelStream()
            .forEach(component -> {

                final var connectedComponents = PCMConnectionHelper
                    .getConnectectedAssemblies(this.modelStorage.getAssembly(), component);
                for (final var connectedComponent : connectedComponents) {
                    final var vulnerabilities = VulnerabilityHelper
                        .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), connectedComponent);

                    final var resource1 = PCMConnectionHelper.getResourceContainer(component,
                            this.modelStorage.getAllocation());
                    final var resource2 = PCMConnectionHelper.getResourceContainer(component,
                            this.modelStorage.getAllocation());

                    this.createEdgeVulnerability(component, connectedComponent, vulnerabilities,
                            this.isConncected(resource1, resource2));
                    this.createEdgeCredentials(component, connectedComponent, this.modelStorage);
                }
            });
    }

    private AttackVector isConncected(final ResourceContainer resource1, final ResourceContainer resource2) {
        final var linking1 = PCMConnectionHelper.getLinkingResource(resource1,
                this.modelStorage.getResourceEnvironment());
        final var linking2 = PCMConnectionHelper.getLinkingResource(resource2,
                this.modelStorage.getResourceEnvironment());

        for (final var linking : linking1) {
            if (linking2.stream()
                .anyMatch(e -> e.getId()
                    .equals(linking.getId()))) {
                return AttackVector.ADJACENT_NETWORK;
            }
        }
        return AttackVector.NETWORK;
    }

    @Override
    public void calculateLinkingResourceToResourcePropagation() {
        this.modelStorage.getResourceEnvironment()
            .getLinkingResources__ResourceEnvironment()
            .parallelStream()
            .forEach(linking -> {
                final var resources = linking.getConnectedResourceContainers_LinkingResource();

                this.createEdgeResourceContainer(linking, resources);

            });

    }

    private void createEdgeResourceContainer(final Entity linking, final List<ResourceContainer> resources) {
        for (final var resource : resources) {

            final var vulnerabilities = VulnerabilityHelper
                .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), resource);
            this.createEdgeVulnerability(linking, resource, vulnerabilities, AttackVector.ADJACENT_NETWORK);
            this.createEdgeCredentials(linking, resource, this.modelStorage);
        }
    }

    @Override
    public void calculateLinkingResourceToAssemblyContextPropagation() {
        this.modelStorage.getResourceEnvironment()
            .getLinkingResources__ResourceEnvironment()
            .parallelStream()
            .forEach(linking -> {
                final var resources = linking.getConnectedResourceContainers_LinkingResource();
                final var components = CollectionHelper.getAssemblyContext(resources,
                        this.modelStorage.getAllocation());
                this.createGraphEdgesComponents(linking, components);

            });

    }

    @Override
    public void calculateResourceContainerToRemoteAssemblyContextPropagation() {
        this.modelStorage.getResourceEnvironment()
            .getResourceContainer_ResourceEnvironment()
            .parallelStream()
            .forEach(resource -> {
                final var reachableResources = PCMConnectionHelper.getConnectedResourceContainers(resource,
                        this.modelStorage.getResourceEnvironment());
                var components = CollectionHelper.getAssemblyContext(reachableResources,
                        this.modelStorage.getAllocation());
                components = components.stream()
                    .filter(e -> !CollectionHelper.isGlobalCommunication(e,
                            this.modelStorage.getVulnerabilitySpecification()
                                .getVulnerabilities()))
                    .toList();
                this.createGraphEdgesComponents(resource, components);
            });

    }

    @Override
    public void calculateResourceContainerToLocalAssemblyContextPropagation() {
        this.modelStorage.getResourceEnvironment()
            .getResourceContainer_ResourceEnvironment()
            .parallelStream()
            .forEach(resource -> {
                final var targetComponents = CollectionHelper.getAssemblyContext(List.of(resource),
                        this.modelStorage.getAllocation());
                for (final var target : targetComponents) {
                    this.createEdgeImplicit(resource, target, this.modelStorage);
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
        this.modelStorage.getResourceEnvironment()
            .getResourceContainer_ResourceEnvironment()
            .parallelStream()
            .forEach(resource -> {

                final var resources = PCMConnectionHelper.getConnectedResourceContainers(resource,
                        this.modelStorage.getResourceEnvironment());
                this.createEdgeResourceContainer(resource, resources);

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
        this.modelStorage.getResourceEnvironment()
            .getResourceContainer_ResourceEnvironment()
            .parallelStream()
            .forEach(resource -> {
                final var linkings = PCMConnectionHelper.getLinkingResource(resource,
                        this.modelStorage.getResourceEnvironment());

                this.createEdgeLinkingResources(resource, linkings);
            });

    }

    /**
     * Calculates the attack graph and stores it internally.
     */
    public void createGraph() {
        // calculate the attack graph in parallel
        final var future = CompletableFuture.allOf(
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
        } catch (final ExecutionException e) {
            LOGGER.log(Level.SEVERE, "Error during graph creation", e);
            Thread.currentThread()
                .interrupt();
            throw new IllegalStateException("IllegalState durin graph creation", e);
        } catch (final InterruptedException e) {
            LOGGER.log(Level.SEVERE, "Error during graph creation", e);
            Thread.currentThread()
                .interrupt();
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
