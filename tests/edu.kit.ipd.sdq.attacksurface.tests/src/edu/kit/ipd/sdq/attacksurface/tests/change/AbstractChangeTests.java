package edu.kit.ipd.sdq.attacksurface.tests.change;

import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.AssemblyContextChangeAssemblyContextsStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.AssemblyContextChangeIsGlobalStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.AssemblyContextChangeResourceContainerStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.AssemblyContextChangeTargetedConnectorsStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.ChangeLinkingResourcesStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.ResourceContainerChangeAssemblyContextsStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackSpecificationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CVEID;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEAttack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEID;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEVulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.ConfidentialityImpact;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Privileges;
import org.palladiosimulator.pcm.confidentiality.context.policy.Category;
import org.palladiosimulator.pcm.confidentiality.context.policy.PermitType;
import org.palladiosimulator.pcm.confidentiality.context.policy.Policy;
import org.palladiosimulator.pcm.confidentiality.context.policy.PolicyFactory;
import org.palladiosimulator.pcm.confidentiality.context.policy.Rule;
import org.palladiosimulator.pcm.confidentiality.context.policy.RuleCombiningAlgorihtm;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

//TODO
import edu.kit.ipd.sdq.attacksurface.core.AttackSurfaceAnalysis;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.tests.AbstractModelTest;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public abstract class AbstractChangeTests extends AbstractModelTest {
    private static final boolean IS_DEBUG = true;

    public AbstractChangeTests() {
        this.PATH_ATTACKER = "simpleAttackmodels-surface/PropagationUnitTests/My.attacker";
        this.PATH_ASSEMBLY = "simpleAttackmodels-surface/PropagationUnitTests/newAssembly.system";
        this.PATH_ALLOCATION = "simpleAttackmodels-surface/PropagationUnitTests/newAllocation.allocation";
        this.PATH_CONTEXT = "simpleAttackmodels-surface/SimpleModelTest/My.context";
        this.PATH_MODIFICATION = "simpleAttackmodels-surface/PropagationUnitTests/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "simpleAttackmodels-surface/PropagationUnitTests/newRepository.repository";
        this.PATH_USAGE = "simpleAttackmodels-surface/PropagationUnitTests/newUsageModel.usagemodel";
        this.PATH_RESOURCES = "simpleAttackmodels-surface/PropagationUnitTests/newResourceEnvironment.resourceenvironment";
    }

    @AfterEach
    @BeforeEach
    protected void resetHashMaps() {
        ChangeLinkingResourcesStorage.getInstance()
        .reset();
        AssemblyContextChangeIsGlobalStorage.getInstance()
        .reset();
        AssemblyContextChangeTargetedConnectorsStorage.getInstance()
        .reset();
        AssemblyContextChangeResourceContainerStorage.getInstance()
        .reset();
        AssemblyContextChangeAssemblyContextsStorage.getInstance()
        .reset();
        ResourceContainerChangeAssemblyContextsStorage.getInstance()
        .reset();
    }

    protected void resetVulnerabilityCache() {
        VulnerabilityHelper.initializeVulnerabilityStorage(this.getBlackboardWrapper()
                .getVulnerabilitySpecification());
    }

    private void addPolicy(final Policy policy) {
        this.context.getPolicyset()
        .getPolicy()
        .add(policy);
    }

    protected CompromisedAssembly createAssembly(final CredentialChange change) {
        return this.createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure()
                .get(0));
    }

    protected CompromisedAssembly createAssembly(final CredentialChange change,
            final AssemblyContext assemblyComponent) {
        final var infectedAssembly = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
        final var assemblyContext = assemblyComponent;
        infectedAssembly.setAffectedElement(assemblyContext);
        change.getCompromisedassembly()
        .add(infectedAssembly);
        return infectedAssembly;
    }

    protected void createAttributeProvider(final UsageSpecification contextSet, final AssemblyContext component) {
        final var attributeProvider = StructureFactory.eINSTANCE.createPCMAttributeProvider();
        attributeProvider.setAssemblycontext(component);
        attributeProvider.setAttribute(contextSet);
        this.context.getPcmspecificationcontainer()
        .getAttributeprovider()
        .add(attributeProvider);
    }

    protected void createAttributeProvider(final UsageSpecification contextSet, final LinkingResource resource) {
        final var attributeProvider = StructureFactory.eINSTANCE.createPCMAttributeProvider();
        attributeProvider.setLinkingresource(resource);
        attributeProvider.setAttribute(contextSet);
        this.context.getPcmspecificationcontainer()
        .getAttributeprovider()
        .add(attributeProvider);
    }

    protected void createAttributeProvider(final UsageSpecification contextSet, final ResourceContainer resource) {
        final var attributeProvider = StructureFactory.eINSTANCE.createPCMAttributeProvider();
        attributeProvider.setResourcecontainer(resource);
        attributeProvider.setAttribute(contextSet);
        this.context.getPcmspecificationcontainer()
        .getAttributeprovider()
        .add(attributeProvider);
    }

    protected void createContextChange(final UsageSpecification context, final CredentialChange change) {
        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(context);
        change.getContextchange()
        .add(contextChange);
    }

    protected CompromisedLinkingResource createLinkingChange(final CredentialChange change) {
        return this.createLinkingChange(change, this.environment.getLinkingResources__ResourceEnvironment()
                .get(0));
    }

    protected CompromisedLinkingResource createLinkingChange(final CredentialChange change,
            final LinkingResource linking) {
        final var linkingChange = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedLinkingResource();
        linkingChange.setAffectedElement(linking);
        change.getCompromisedlinkingresource()
        .add(linkingChange);
        return linkingChange;
    }

    protected void createPolicyEntity(final UsageSpecification usageSpecification, final Entity entity) {
        final var policy = PolicyFactory.eINSTANCE.createPolicy();
        policy.setCombiningAlgorithm(RuleCombiningAlgorihtm.DENY_UNLESS_PERMIT);

        final var match = StructureFactory.eINSTANCE.createEntityMatch();
        match.setCategory(Category.RESOURCE);
        match.setEntity(entity);
        final var allOff = PolicyFactory.eINSTANCE.createAllOf();
        allOff.getMatch()
        .add(match);
        policy.getTarget()
        .add(allOff);

        final var rule = PolicyFactory.eINSTANCE.createRule();

        final var simpleExpression = PolicyFactory.eINSTANCE.createSimpleAttributeCondition();
        simpleExpression.setAttribute(usageSpecification);

        rule.setCondition(simpleExpression);
        rule.setPermit(PermitType.PERMIT);

        policy.getRule()
        .add(rule);

        this.addPolicy(policy);
    }

    protected CompromisedResource createResourceChange(final CredentialChange change) {
        return this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment()
                .get(0));

    }

    protected CompromisedResource createResourceChange(final CredentialChange change,
            final ResourceContainer resource) {
        final var infectedResource = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
        infectedResource.setAffectedElement(resource);
        change.getCompromisedresource()
        .add(infectedResource);
        return infectedResource;
    }

    protected CWEID createCWEID(final int id) {
        final var cweID = AttackSpecificationFactory.eINSTANCE.createCWEID();
        cweID.setCweID(id);
        return cweID;
    }

    protected CWEID createCWEID(final int id, final CWEID parent) {
        final var cweID = this.createCWEID(id);
        parent.getChildren()
        .add(cweID);
        return cweID;
    }

    protected CVEID createCVEID(final String id) {
        final var cweID = AttackSpecificationFactory.eINSTANCE.createCVEID();
        cweID.setCveID(id);
        return cweID;
    }

    protected CWEAttack createCWEAttack(final CWEID id) {
        final var cweAttack = AttackSpecificationFactory.eINSTANCE.createCWEAttack();
        cweAttack.setCategory(id);
        return cweAttack;
    }

    protected CWEVulnerability createCWEVulnerability(final CWEID id, final AttackVector vector,
            final Privileges privileges, final ConfidentialityImpact impact, final boolean takeOver,
            final UsageSpecification gainedAttributes) {
        final var vulnerability = AttackSpecificationFactory.eINSTANCE.createCWEVulnerability();
        vulnerability.getCweID()
        .add(id);
        vulnerability.setAttackVector(vector);
        vulnerability.setPrivileges(privileges);
        vulnerability.setConfidentialityImpact(impact);
        vulnerability.setTakeOver(takeOver);
        if (gainedAttributes != null) {
            vulnerability.getGainedAttributes()
            .add(gainedAttributes);
        }
        return vulnerability;
    }

    protected CWEVulnerability createCWEVulnerability(final CWEID id, final boolean takeOver,
            final boolean gainRootAccess) {
        return this.createCWEVulnerability(id, AttackVector.NETWORK, Privileges.NONE, ConfidentialityImpact.HIGH,
                takeOver, gainRootAccess ? this.createRootCredentialsIfNecessary() : null);
    }

    protected CWEID createSimpleAttack() {
        final var cweID = this.createCWEID(1);
        final var attack = this.createCWEAttack(cweID);
        this.attacker.getAttackers()
        .getAttacker()
        .get(0)
        .getAttacks()
        .add(attack);
        return cweID;
    }

    //    protected void integrateRoot(final Entity entity) {
    //        final var rootCred = this.createRootCredentialsIfNecessary();
    //
    //        final var sysInteg = PcmIntegrationFactory.eINSTANCE.createCredentialSystemIntegration();
    //        sysInteg.setPcmelement(PCMElementType.typeOf(entity)
    //            .toPCMElement(entity));
    //
    //        sysInteg.setCredential(rootCred);
    //        this.attacker.getSystemintegration()
    //            .getVulnerabilities()
    //            .add(sysInteg);
    //        this.context.getPolicyset()
    //            .setCombiningAlgorithm(PolicyCombiningAlgorithm.DENY_UNLESS_PERMIT);
    //        this.context.getPolicyset()
    //            .getPolicy()
    //            .add(this.toPolicy(entity, rootCred));
    //    }

    private Policy toPolicy(final Entity entity, final UsageSpecification credentials) {
        final var policy = PolicyFactory.eINSTANCE.createPolicy();
        policy.getRule()
        .add(this.toRule(entity, credentials));
        return policy;
    }

    private Rule toRule(final Entity entity, final UsageSpecification credentials) {
        final var rule = PolicyFactory.eINSTANCE.createRule();
        rule.setPermit(PermitType.PERMIT);
        final var allOf = PolicyFactory.eINSTANCE.createAllOf();
        final var entityMatch = StructureFactory.eINSTANCE.createEntityMatch();
        entityMatch.setCategory(Category.RESOURCE);
        entityMatch.setEntity(entity);
        allOf.getMatch()
        .add(entityMatch);
        rule.getTarget()
        .add(allOf);
        final var condition = PolicyFactory.eINSTANCE.createSimpleAttributeCondition();
        condition.setCategory(Category.SUBJECT);
        condition.setMustBePresent(true);
        condition.setAttribute(credentials);
        rule.setCondition(condition);
        return rule;
    }

    protected boolean isInGraph(final Entity entity) {
        //        final var node =
        //        return node != null;
        return false;
    }

    protected void assertCompromisationStatus(final boolean isCompromised, final boolean isAttacked,
            final Entity entity, final String causeId) {
        //        final var node = getAttackGraph().findNode(new AttackNodeContent(entity));
        //        if (node != null) {
        //            Assertions.assertEquals(isCompromised, node.isCompromised());
        //            Assertions.assertEquals(isAttacked, node.isAttacked());
        //            if (causeId != null) {
        //                Assertions.assertTrue(getAttackGraph().getCompromisationCauseIds(node).stream().anyMatch(i -> Objects.equals(i.getId(), causeId)));
        //            }
        //        } else {
        //            Assertions.assertFalse(isAttacked);
        //            Assertions.assertFalse(isCompromised);
        //        }

        fail();
    }

    protected ResourceContainer getResource(final List<AssemblyContext> assemblyList) {
        final var assembly = assemblyList.get(0);
        final var resourceOpt = this.allocation.getAllocationContexts_Allocation()
                .stream()
                .filter(e -> EcoreUtil.equals(e.getAssemblyContext_AllocationContext(), assembly))
                .map(AllocationContext::getResourceContainer_AllocationContext)
                .findAny();
        if (resourceOpt.isEmpty()) {
            fail("Wrong Test Input");
        }
        return resourceOpt.orElse(null);
    }

    protected List<LinkingResource> getLinkingResource(final ResourceContainer container) {
        return this.environment.getLinkingResources__ResourceEnvironment()
                .stream()
                .filter(e -> e.getConnectedResourceContainers_LinkingResource()
                        .stream()
                        .anyMatch(f -> EcoreUtil.equals(f, container)))
                .collect(Collectors.toList());
    }

    protected List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource) {
        final var resources = this.getLinkingResource(resource)
                .stream()
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource()
                        .stream())
                .distinct()
                .filter(e -> !EcoreUtil.equals(e, resource))
                .collect(Collectors.toList());
        return resources;
    }

    protected CredentialChange runAnalysis() {
        this.generateXML();
        final var modelStorage = this.getBlackboardWrapper();
        final var analysis = new AttackSurfaceAnalysis();
        analysis.runChangePropagationAnalysis(modelStorage);
        return this.modification.getChangePropagationSteps()
                .get(0);
    }

    protected CredentialChange runAnalysisWithoutAttackPathGeneration() {
        return this.runAnalysis();
    }

    //    protected AttackEdge toEdge(AttackStatusEdgeContent content, Entity attacker, Entity attacked) {
    //        return new AttackEdge(attacker, attacked, null, null);

    //
    //                AttackStatusEdge(content,
    //                EndpointPair.ordered(
    //                        new AttackNodeContent(attacker),
    //                        new AttackNodeContent(attacked)));
    //    }

    protected void doDebugSysOutExpectedAndUnexpectedPaths(final Set<AttackPathSurface> expectedPathsSet,
            final Set<AttackPathSurface> attackPaths) {
        if (IS_DEBUG) {
            attackPaths.forEach(p -> System.out.println(p));
            System.out.println("--------------------------------\nexpected:");
            expectedPathsSet.forEach(p -> System.out.println(p));
            System.out.println("--------------------------------\nunexpected (is there, but should not be there):");
            attackPaths.forEach(p -> {
                if (!expectedPathsSet.contains(p)) {
                    System.out.println(p);
                }
            });
            System.out.println("--------------------------------\nunexpected (should be there, but is not there):");
            expectedPathsSet.forEach(p -> {
                if (!attackPaths.contains(p)) {
                    System.out.println(p);
                }
            });
        }
    }

    protected void generateGraph(final boolean createCauselessEdges) {
        //        final var dot = new DotCreation();
        //        final var graph = getAttackGraph().getStringGraph(createCauselessEdges);
        //        System.out.println(graph);
        //        var dotStr = dot.createOutputFormat(graph);
        //        try {
        //            var file = Files.createTempFile("test", ".dot");
        //
        //            System.out.println(file.toAbsolutePath());
        //            Files.writeString(file.toAbsolutePath(), dotStr);
        //            var command = String.format("dot -Tpng %s", file.toAbsolutePath().toString());
        //            var process = Runtime.getRuntime().exec(command);
        //
        //            var outputFile = Files.createTempFile("test", ".png");
        //            var outputStream = Files.newOutputStream(outputFile.toAbsolutePath());
        //            process.getInputStream().transferTo(outputStream);
        //
        //            var errorStream = new ByteArrayOutputStream();
        //            process.getErrorStream().transferTo(errorStream);
        //            if (errorStream.size() != 0) {
        //                System.err.println(errorStream.toString());
        //            }
        //        } catch (IOException e) {
        //            e.printStackTrace();
        //        }
    }
}
