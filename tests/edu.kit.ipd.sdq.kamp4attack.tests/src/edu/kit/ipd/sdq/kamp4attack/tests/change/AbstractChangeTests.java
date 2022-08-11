package edu.kit.ipd.sdq.kamp4attack.tests.change;

import org.junit.jupiter.api.BeforeEach;
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
import org.palladiosimulator.pcm.confidentiality.context.policy.RuleCombiningAlgorihtm;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.AttackPropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.core.CacheVulnerability;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.tests.AbstractModelTest;

public abstract class AbstractChangeTests extends AbstractModelTest {

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

    protected CWEID createSimpleAttack() {
        final var cweID = this.createCWEID(1);
        final var attack = createCWEAttack(cweID);
        this.attacker.getAttackers().getAttacker().get(0).getAttacks().add(attack);
        return cweID;
    }

    protected void runAnalysis() {
        generateXML();
        final var board = getBlackboardWrapper();
        final var analysis = new AttackPropagationAnalysis();
        analysis.runChangePropagationAnalysis(board);
    }

    @BeforeEach
    void clearCache() {
        CachePDP.instance().clearCache();
        CacheCompromised.instance().reset();
        CacheVulnerability.instance().reset();
    }

}
