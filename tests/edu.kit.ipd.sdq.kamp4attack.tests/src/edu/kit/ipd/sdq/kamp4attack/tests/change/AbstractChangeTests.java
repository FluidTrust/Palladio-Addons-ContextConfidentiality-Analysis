package edu.kit.ipd.sdq.kamp4attack.tests.change;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackSpecificationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CVEID;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEAttack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEID;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEVulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.ConfidentialityImpact;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Privileges;
import org.palladiosimulator.pcm.confidentiality.context.model.ContextAttribute;
import org.palladiosimulator.pcm.confidentiality.context.model.ModelFactory;
import org.palladiosimulator.pcm.confidentiality.context.model.SingleAttributeContext;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.set.SetFactory;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AssemblyFactory;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.SystemPolicySpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

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
        this.PATH_CONTEXT = "simpleAttackmodels/PropagationUnitTests/My.context";
        this.PATH_MODIFICATION = "simpleAttackmodels/PropagationUnitTests/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "simpleAttackmodels/PropagationUnitTests/newRepository.repository";
        this.PATH_USAGE = "simpleAttackmodels/PropagationUnitTests/newUsageModel.usagemodel";
        this.PATH_RESOURCES = "simpleAttackmodels/PropagationUnitTests/newResourceEnvironment.resourceenvironment";
    }

    private void addPolicy(final ContextSet contextSet, final SystemPolicySpecification policyAssembly) {
        policyAssembly.getPolicy().add(contextSet);
        this.context.getPcmspecificationcontainer().getPolicyspecification().add(policyAssembly);
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

    protected void createAttributeProvider(final ContextSet contextSet, final AssemblyContext component) {
        final var attributeProvider = AssemblyFactory.eINSTANCE.createAttributeProvider();
        attributeProvider.setAssemblycontext(component);
        attributeProvider.setContextset(contextSet);
        this.context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
    }

    protected void createAttributeProvider(final ContextSet contextSet, final LinkingResource resource) {
        final var attributeProvider = AssemblyFactory.eINSTANCE.createAttributeProvider();
        attributeProvider.setLinkingresource(resource);
        attributeProvider.setContextset(contextSet);
        this.context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
    }

    protected void createAttributeProvider(final ContextSet contextSet, final ResourceContainer resource) {
        final var attributeProvider = AssemblyFactory.eINSTANCE.createAttributeProvider();
        attributeProvider.setResourcecontainer(resource);
        attributeProvider.setContextset(contextSet);
        this.context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
    }

    protected SingleAttributeContext createContext(final String name) {
        final var contextAccess = ModelFactory.eINSTANCE.createSingleAttributeContext();
        contextAccess.setEntityName(name);
        this.context.getContextContainer().get(0).getContext().add(contextAccess);
        return contextAccess;
    }

    protected void createContextChange(final ContextAttribute context, final CredentialChange change) {
        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(context);
        change.getContextchange().add(contextChange);
    }

    protected ContextSet createContextSet(final SingleAttributeContext contextAccess) {
        final var contextSetAccessResource = SetFactory.eINSTANCE.createContextSet();
        contextSetAccessResource.getContexts().add(contextAccess);
        this.context.getSetContainer().get(0).getPolicies().add(contextSetAccessResource);
        return contextSetAccessResource;
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

    protected void createPolicyAssembly(final ContextSet contextSet, final AssemblyContext assemblyComponent) {
        final var policyAssembly = AssemblyFactory.eINSTANCE.createSystemPolicySpecification();
        policyAssembly.setAssemblycontext(assemblyComponent);
        this.addPolicy(contextSet, policyAssembly);
    }

    protected void createPolicyLinking(final ContextSet contextSet, final LinkingResource linking) {
        final var policyLinking = AssemblyFactory.eINSTANCE.createSystemPolicySpecification();
        policyLinking.setLinkingresource(linking);
        this.addPolicy(contextSet, policyLinking);
    }

    protected void createPolicyResource(final ContextSet contextSet, final ResourceContainer resource) {
        final var policyResource = AssemblyFactory.eINSTANCE.createSystemPolicySpecification();
        policyResource.setResourcecontainer(resource);
        this.addPolicy(contextSet, policyResource);
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
            final ContextSet requiredCredentials, final ContextSet gainedCredentials) {
        final var vulnerability = AttackSpecificationFactory.eINSTANCE.createCWEVulnerability();
        vulnerability.getCweID().add(id);
        vulnerability.setAttackVector(vector);
        vulnerability.setPrivileges(privileges);
        vulnerability.setConfidentialityImpact(impact);
        vulnerability.setTakeOver(takeOver);
        if (requiredCredentials != null) {
            vulnerability.setRequiredCredentials(requiredCredentials);
        }
        if (gainedCredentials != null) {
            vulnerability.getGainedPrivilege().add(gainedCredentials);
        }
        return vulnerability;
    }

    protected CWEID createSimpleAttack() {
        final var cweID = this.createCWEID(1);
        final var attack = this.createCWEAttack(cweID);
        this.attacker.getAttackers().getAttacker().get(0).getAttacks().add(attack);
        return cweID;
    }

}
