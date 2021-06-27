package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp;

import java.nio.file.Path;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.palladiosimulator.pcm.confidentiality.accessControl.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.policy.Policy;
import org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.XACMLGeneration;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl.PolicyHandler;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.io.XACMLPolicyWriter;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicySetType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicyType;

@Component
public class XACMLGenerator implements XACMLGeneration {
    @Reference(service = PolicyHandler.class)
    private ContextTypeConverter<PolicyType, Policy> handler;

    public XACMLGenerator() {
    }

    @Override
    public void generateXACML(PCMBlackBoard pcm, ConfidentialAccessSpecification confidentialitySpecification) {
        var set = createPolicySet(pcm.getSystem().getEntityName());

        XACMLPolicyWriter.writePolicyFile(Path.of("/home/majuwa/tmp/test.xml"), set);
        this.handler.transform(confidentialitySpecification.getPolicyset().getPolicy().get(0));
    }

    private PolicySetType createPolicySet(String name) {
        var set = new ObjectFactory().createPolicySetType();

        set.setDescription("Policies for " + name + ". Automatically created by Palladio-XACML-Integration");
        return set;
    }

}
