package edu.kit.ipd.sdq.kamp4attack.tests;

import org.palladiosimulator.pcm.confidentiality.context.model.ModelFactory;
import org.palladiosimulator.pcm.confidentiality.context.model.SingleAttributeContext;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.set.SetFactory;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AssemblyFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

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
    
    protected SingleAttributeContext createContext(String name) {
        var contextAccess = ModelFactory.eINSTANCE.createSingleAttributeContext();
        contextAccess.setEntityName(name);
        context.getContextContainer().get(0).getContext().add(contextAccess);
        return contextAccess;
    }
    
    protected ContextSet createContextSet(SingleAttributeContext contextAccess) {
        var contextSetAccessResource = SetFactory.eINSTANCE.createContextSet();
        contextSetAccessResource.getContexts().add(contextAccess);
        context.getSetContainer().get(0).getPolicies().add(contextSetAccessResource);
        return contextSetAccessResource;
    }
    
    protected void createAttributeProvider(ContextSet contextSet, AssemblyContext component) {
        var attributeProvider = AssemblyFactory.eINSTANCE.createAttributeProvider();
        attributeProvider.setAssemblycontext(component);
        attributeProvider.setContextset(contextSet);
        context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
    }
}
