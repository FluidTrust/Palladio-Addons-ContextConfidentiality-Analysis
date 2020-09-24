package edu.kit.ipd.sdq.kamp4attack.tests;

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

public abstract class AbstractChangeTests extends AbstractModelTest {

    public AbstractChangeTests() {
        this.PATH_ATTACKER = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/My.attacker";
        this.PATH_ASSEMBLY = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/newAssembly.system";
        this.PATH_ALLOCATION = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/newAllocation.allocation";
        this.PATH_CONTEXT = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/My.context";
        this.PATH_MODIFICATION = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/newRepository.repository";
        this.PATH_USAGE = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/newUsageModel.usagemodel";
        this.PATH_RESOURCES = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/newResourceEnvironment.resourceenvironment";
    }

    @Override
    void execute() {

    }

    protected SingleAttributeContext createContext(final String name) {
        final var contextAccess = ModelFactory.eINSTANCE.createSingleAttributeContext();
        contextAccess.setEntityName(name);
        this.context.getContextContainer().get(0).getContext().add(contextAccess);
        return contextAccess;
    }

    protected ContextSet createContextSet(final SingleAttributeContext contextAccess) {
        final var contextSetAccessResource = SetFactory.eINSTANCE.createContextSet();
        contextSetAccessResource.getContexts().add(contextAccess);
        this.context.getSetContainer().get(0).getPolicies().add(contextSetAccessResource);
        return contextSetAccessResource;
    }

    protected void createAttributeProvider(final ContextSet contextSet, final AssemblyContext component) {
        final var attributeProvider = AssemblyFactory.eINSTANCE.createAttributeProvider();
        attributeProvider.setAssemblycontext(component);
        attributeProvider.setContextset(contextSet);
        this.context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
    }

    protected void createAttributeProvider(final ContextSet contextSet, final ResourceContainer resource) {
        final var attributeProvider = AssemblyFactory.eINSTANCE.createAttributeProvider();
        attributeProvider.setResourcecontainer(resource);
        attributeProvider.setContextset(contextSet);
        this.context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
    }

    protected void createAttributeProvider(final ContextSet contextSet, final LinkingResource resource) {
        final var attributeProvider = AssemblyFactory.eINSTANCE.createAttributeProvider();
        attributeProvider.setLinkingresource(resource);
        attributeProvider.setContextset(contextSet);
        this.context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
    }

    protected CompromisedAssembly createAssembly(final CredentialChange change) {
        return createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
    }

    protected CompromisedAssembly createAssembly(final CredentialChange change, AssemblyContext assemblyComponent) {
        final var infectedAssembly = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
        final var assemblyContext = assemblyComponent;
        infectedAssembly.setAffectedElement(assemblyContext);
        change.getCompromisedassembly().add(infectedAssembly);
        return infectedAssembly;
    }

    protected void createPolicyAssembly(final ContextSet contextSet, AssemblyContext assemblyComponent) {
        final var policyAssembly = AssemblyFactory.eINSTANCE.createSystemPolicySpecification();
        policyAssembly.setAssemblycontext(assemblyComponent);
        addPolicy(contextSet, policyAssembly);
    }

    private void addPolicy(final ContextSet contextSet, final SystemPolicySpecification policyAssembly) {
        policyAssembly.getPolicy().add(contextSet);
        this.context.getPcmspecificationcontainer().getPolicyspecification().add(policyAssembly);
    }

    protected void createPolicyResource(final ContextSet contextSet, final ResourceContainer resource) {
        final var policyResource = AssemblyFactory.eINSTANCE.createSystemPolicySpecification();
        policyResource.setResourcecontainer(resource);
        addPolicy(contextSet, policyResource);
    }

    protected void createPolicyLinking(final ContextSet contextSet, final LinkingResource linking) {
        final var policyLinking = AssemblyFactory.eINSTANCE.createSystemPolicySpecification();
        policyLinking.setLinkingresource(linking);
        addPolicy(contextSet, policyLinking);
    }

    protected void createContextChange(final ContextAttribute context, final CredentialChange change) {
        var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(context);
        change.getContextchange().add(contextChange);
    }

    protected CompromisedResource createResourceChange(final CredentialChange change) {
        return createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment().get(0));

    }

    protected CompromisedResource createResourceChange(final CredentialChange change, ResourceContainer resource) {
        final var infectedResource = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
        infectedResource.setAffectedElement(resource);
        change.getCompromisedresource().add(infectedResource);
        return infectedResource;
    }

    protected CompromisedLinkingResource createLinkingChange(CredentialChange change) {
        return createLinkingChange(change, this.environment.getLinkingResources__ResourceEnvironment().get(0));
    }

    protected CompromisedLinkingResource createLinkingChange(CredentialChange change, LinkingResource linking) {
        var linkingChange = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedLinkingResource();
        linkingChange.setAffectedElement(linking);
        change.getCompromisedlinkingresource().add(linkingChange);
        return linkingChange;
    }

}
