package edu.kit.ipd.sdq.kamp4attack.tests;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.emf.ecore.resource.Resource;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSpecification;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testframework.BaseTest;
import org.palladiosimulator.pcm.confidentiality.context.system.SystemFactory;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.DataTypes;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemcontextFactory;
import org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.XACMLGenerator;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.system.System;

import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository;

public abstract class AbstractModelTest extends BaseTest {

    protected String PATH_ATTACKER;
    protected String PATH_ASSEMBLY;
    protected String PATH_ALLOCATION;
    protected String PATH_CONTEXT;
    protected String PATH_MODIFICATION;
    protected String PATH_REPOSITORY;
    protected String PATH_USAGE;
    protected String PATH_RESOURCES;

    protected System assembly;
    protected ResourceEnvironment environment;
    protected Allocation allocation;
    protected ConfidentialAccessSpecification context;
    protected AttackerSpecification attacker;
    protected KAMP4attackModificationRepository modification;

    private String pathXACML = "test.xml";

    final protected BlackboardWrapper getBlackboardWrapper() {

        return new BlackboardWrapper(this.modification, this.assembly, this.environment, this.allocation,
                this.context.getPcmspecificationcontainer(), this.attacker.getSystemintegration(), this.eval);
    }

    @Override
    protected List<String> getModelsPath() {
        final var list = new ArrayList<String>();

        list.add(this.PATH_ASSEMBLY);
        list.add(this.PATH_ALLOCATION);
        list.add(this.PATH_RESOURCES);
        list.add(this.PATH_USAGE);
        list.add(this.PATH_CONTEXT);
        list.add(this.PATH_ATTACKER);
        list.add(this.PATH_MODIFICATION);

        return list;
    }

    @Override
    protected void assignValues(final List<Resource> list) {
        this.assembly = this.getModel(list, System.class);
        this.environment = this.getModel(list, ResourceEnvironment.class);
        this.allocation = this.getModel(list, Allocation.class);
        this.context = this.getModel(list, ConfidentialAccessSpecification.class);
        this.attacker = this.getModel(list, AttackerSpecification.class);
        this.modification = getModel(list, KAMP4attackModificationRepository.class);
    }

    @Override
    protected void generateXML() {
        var generator = new XACMLGenerator();
        var blackboard = new PCMBlackBoard(this.assembly, null, this.environment);
        generator.generateXACML(blackboard, this.context, this.pathXACML);
    }

    protected UsageSpecification createContext(final String name) {
        final var contextAccess = SystemFactory.eINSTANCE.createUsageSpecification();

        final var attribute = SystemcontextFactory.eINSTANCE.createSimpleAttribute();
        var attributeValue = SystemcontextFactory.eINSTANCE.createAttributeValue();
        attributeValue.getValues().add(name);
        attributeValue.setType(DataTypes.STRING);
        attribute.getAttributevalue().add(attributeValue);

        contextAccess.setEntityName(name);
        contextAccess.setAttribute(attribute);
        contextAccess.setAttributevalue(attributeValue);
        this.context.getAttributes().getAttribute().add(attribute);
        this.context.getPcmspecificationcontainer().getUsagespecification().add(contextAccess);
        return contextAccess;
    }

}