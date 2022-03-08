package edu.kit.ipd.sdq.attacksurface.tests.change;

import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackSpecificationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CVEID;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEAttack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEID;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEVulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.ConfidentialityImpact;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Privileges;
import org.palladiosimulator.pcm.confidentiality.context.ContextFactory;
import org.palladiosimulator.pcm.confidentiality.context.policy.AllOf;
import org.palladiosimulator.pcm.confidentiality.context.policy.Category;
import org.palladiosimulator.pcm.confidentiality.context.policy.PermitType;
import org.palladiosimulator.pcm.confidentiality.context.policy.Policy;
import org.palladiosimulator.pcm.confidentiality.context.policy.PolicyCombiningAlgorithm;
import org.palladiosimulator.pcm.confidentiality.context.policy.PolicyFactory;
import org.palladiosimulator.pcm.confidentiality.context.policy.Rule;
import org.palladiosimulator.pcm.confidentiality.context.policy.RuleCombiningAlgorihtm;
import org.palladiosimulator.pcm.confidentiality.context.policy.SimpleAttributeCondition;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.EntityMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructurePackage;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;


//TODO
import edu.kit.ipd.sdq.attacksurface.core.AttackSurfaceAnalysis;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.attacksurface.tests.AbstractModelTest;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;

public abstract class AbstractChangeTests extends AbstractModelTest {
    //TODO

    public AbstractChangeTests() {
        this.PATH_ATTACKER = "simpleAttackmodels/PropagationUnitTests/My.attacker";
        this.PATH_ASSEMBLY = "simpleAttackmodels/PropagationUnitTests/newAssembly.system";
        this.PATH_ALLOCATION = "simpleAttackmodels/PropagationUnitTests/newAllocation.allocation";
        this.PATH_CONTEXT = "simpleAttackmodels/SimpleModelTest/My.context";
        this.PATH_MODIFICATION = "simpleAttackmodels/PropagationUnitTests/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "simpleAttackmodels/PropagationUnitTests/newRepository.repository";
        this.PATH_USAGE = "simpleAttackmodels/PropagationUnitTests/newUsageModel.usagemodel";
        this.PATH_RESOURCES = "simpleAttackmodels/PropagationUnitTests/newResourceEnvironment.resourceenvironment";
    }

    private void addPolicy(final Policy policy) {
        this.context.getPolicyset().getPolicy().add(policy);
    }

    protected CompromisedAssembly createAssembly(final CredentialChange change) {
        return this.createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
    }

    protected CompromisedAssembly createAssembly(final CredentialChange change,
            final AssemblyContext assemblyComponent) {
        final var infectedAssembly = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
        final var assemblyContext = assemblyComponent;
        infectedAssembly.setAffectedElement(assemblyContext);
        change.getCompromisedassembly().add(infectedAssembly);
        return infectedAssembly;
    }

    protected void createAttributeProvider(final UsageSpecification contextSet, final AssemblyContext component) {
        final var attributeProvider = StructureFactory.eINSTANCE.createPCMAttributeProvider();
        attributeProvider.setAssemblycontext(component);
        attributeProvider.setAttribute(contextSet);
        this.context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
    }

    protected void createAttributeProvider(final UsageSpecification contextSet, final LinkingResource resource) {
        final var attributeProvider = StructureFactory.eINSTANCE.createPCMAttributeProvider();
        attributeProvider.setLinkingresource(resource);
        attributeProvider.setAttribute(contextSet);
        this.context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
    }

    protected void createAttributeProvider(final UsageSpecification contextSet, final ResourceContainer resource) {
        final var attributeProvider = StructureFactory.eINSTANCE.createPCMAttributeProvider();
        attributeProvider.setResourcecontainer(resource);
        attributeProvider.setAttribute(contextSet);
        this.context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
    }


    protected void createContextChange(final UsageSpecification context, final CredentialChange change) {
        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(context);
        change.getContextchange().add(contextChange);
    }

    protected CompromisedLinkingResource createLinkingChange(final CredentialChange change) {
        return this.createLinkingChange(change, this.environment.getLinkingResources__ResourceEnvironment().get(0));
    }

    protected CompromisedLinkingResource createLinkingChange(final CredentialChange change,
            final LinkingResource linking) {
        final var linkingChange = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedLinkingResource();
        linkingChange.setAffectedElement(linking);
        change.getCompromisedlinkingresource().add(linkingChange);
        return linkingChange;
    }

    protected void createPolicyEntity(final UsageSpecification usageSpecification, final Entity entity) {
        final var policy = PolicyFactory.eINSTANCE.createPolicy();
        policy.setCombiningAlgorithm(RuleCombiningAlgorihtm.DENY_UNLESS_PERMIT);

        var match = StructureFactory.eINSTANCE.createEntityMatch();
        match.setCategory(Category.RESOURCE);
        match.setEntity(entity);
        var allOff = PolicyFactory.eINSTANCE.createAllOf();
        allOff.getMatch().add(match);
        policy.getTarget().add(allOff);

        var rule = PolicyFactory.eINSTANCE.createRule();

        var simpleExpression = PolicyFactory.eINSTANCE.createSimpleAttributeCondition();
        simpleExpression.setAttribute(usageSpecification);

        rule.setCondition(simpleExpression);
        rule.setPermit(PermitType.PERMIT);

        policy.getRule().add(rule);

        addPolicy(policy);
    }

    protected CompromisedResource createResourceChange(final CredentialChange change) {
        return this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment().get(0));

    }

    protected CompromisedResource createResourceChange(final CredentialChange change,
            final ResourceContainer resource) {
        final var infectedResource = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
        infectedResource.setAffectedElement(resource);
        change.getCompromisedresource().add(infectedResource);
        return infectedResource;
    }

    protected CWEID createCWEID(final int id) {
        final var cweID = AttackSpecificationFactory.eINSTANCE.createCWEID();
        cweID.setCweID(id);
        return cweID;
    }

    protected CWEID createCWEID(final int id, final CWEID parent) {
        final var cweID = this.createCWEID(id);
        parent.getChildren().add(cweID);
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
        vulnerability.getCweID().add(id);
        vulnerability.setAttackVector(vector);
        vulnerability.setPrivileges(privileges);
        vulnerability.setConfidentialityImpact(impact);
        vulnerability.setTakeOver(takeOver);
        if (gainedAttributes != null) {
            vulnerability.getGainedAttributes().add(gainedAttributes);
        }
        return vulnerability;
    }
    
    protected CWEVulnerability createCWEVulnerability(final CWEID id, final boolean takeOver,
            final boolean gainRootAccess) {
        return createCWEVulnerability(id, AttackVector.NETWORK, Privileges.NONE, ConfidentialityImpact.HIGH, 
                takeOver, gainRootAccess ? createRootCredentialsIfNecessary() : null);
    }

    protected CWEID createSimpleAttack() {
        final var cweID = this.createCWEID(1);
        final var attack = createCWEAttack(cweID);
        this.attacker.getAttackers().getAttacker().get(0).getAttacks().add(attack);
        return cweID;
    }
    
    protected void integrateVulnerability(final Entity entity, final Vulnerability vulnerability) {
        this.attacker.getVulnerabilites().getVulnerability().add(vulnerability);
        final var sysInteg = PcmIntegrationFactory.eINSTANCE.createVulnerabilitySystemIntegration();
        sysInteg.setPcmelement(PCMElementType.typeOf(entity).toPCMElement(entity));
        sysInteg.setVulnerability(vulnerability);
        this.attacker.getSystemintegration().getVulnerabilities().add(sysInteg);  
        addAllPossibleAttacks();
    }
    
    protected void integrateRoot(final Entity entity) {
        final var rootCred = createRootCredentialsIfNecessary();
        
        final var sysInteg = PcmIntegrationFactory.eINSTANCE.createCredentialSystemIntegration();
        sysInteg.setPcmelement(PCMElementType.typeOf(entity).toPCMElement(entity));
        
        sysInteg.setCredential(rootCred);
        this.attacker.getSystemintegration().getVulnerabilities().add(sysInteg);
        this.context.getPolicyset().setCombiningAlgorithm(PolicyCombiningAlgorithm.DENY_UNLESS_PERMIT);
        this.context.getPolicyset().getPolicy().add(toPolicy(entity, rootCred));
    }

    private Policy toPolicy(final Entity entity, final UsageSpecification credentials) {
        final Policy policy = PolicyFactory.eINSTANCE.createPolicy();
        policy.getRule().add(toRule(entity, credentials));
        return policy;
    }

    private Rule toRule(Entity entity, UsageSpecification credentials) {
        final Rule rule = PolicyFactory.eINSTANCE.createRule();
        rule.setPermit(PermitType.PERMIT);
        final AllOf allOf = PolicyFactory.eINSTANCE.createAllOf();
        final EntityMatch entityMatch = StructureFactory.eINSTANCE.createEntityMatch();
        entityMatch.setCategory(Category.RESOURCE);
        entityMatch.setEntity(entity);
        allOf.getMatch().add(entityMatch);
        rule.getTarget().add(allOf);
        final SimpleAttributeCondition condition = PolicyFactory.eINSTANCE.createSimpleAttributeCondition();
        condition.setCategory(Category.SUBJECT);
        condition.setMustBePresent(true);
        condition.setAttribute(credentials);
        rule.setCondition(condition);
        return rule;
    }

    protected boolean isInGraph(final Entity entity) {
        final var node = this.getAttackGraph().findNode(new AttackStatusNodeContent(entity));
        return node != null;
    }
    
    protected void assertCompromisationStatus(final boolean isCompromised, final boolean isAttacked,
            final Entity entity, 
            final String causeId) {
        final var node = this.getAttackGraph().findNode(new AttackStatusNodeContent(entity));
        if (node != null) {
            Assert.assertEquals(isCompromised, node.isCompromised());
            Assert.assertEquals(isAttacked, node.isAttacked());
            if (causeId != null) {
                Assert.assertTrue(getAttackGraph().getCompromisationCauseIds(node).contains(causeId));
            }
        } else {
            Assert.assertFalse(isAttacked);
            Assert.assertFalse(isCompromised);
        }
    }
    

    protected ResourceContainer getResource(final AssemblyContext assembly) {
        final var resourceOpt = this.allocation.getAllocationContexts_Allocation().stream()
                .filter(e -> EcoreUtil.equals(e.getAssemblyContext_AllocationContext(), assembly))
                .map(AllocationContext::getResourceContainer_AllocationContext).findAny();
        if (resourceOpt.isEmpty()) {
            fail("Wrong Test Input");
        }
        return resourceOpt.orElse(null);
    }
    
    protected List<LinkingResource> getLinkingResource(final ResourceContainer container) {
        return this.environment.getLinkingResources__ResourceEnvironment().stream()
                .filter(e -> e.getConnectedResourceContainers_LinkingResource().stream()
                        .anyMatch(f -> EcoreUtil.equals(f, container)))
                .collect(Collectors.toList());
    }

    protected List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource) {
        final var resources = getLinkingResource(resource).stream()
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream()).distinct()
                .filter(e -> !EcoreUtil.equals(e, resource)).collect(Collectors.toList());
        return resources;
    }

    protected void runAnalysis() {
        generateXML();
        final var board = getBlackboardWrapper();
        final var analysis = new AttackSurfaceAnalysis();
        analysis.runChangePropagationAnalysis(board);
    }
}
