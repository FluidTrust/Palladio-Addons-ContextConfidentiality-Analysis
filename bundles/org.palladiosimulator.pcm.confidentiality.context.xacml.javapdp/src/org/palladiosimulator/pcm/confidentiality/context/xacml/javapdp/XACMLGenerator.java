package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp;

import java.nio.file.Path;
import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.policy.PolicySet;
import org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.XACMLGeneration;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl.PolicySetHandler;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util.XACMLPolicyWriter;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicySetType;

@Component(service = XACMLGeneration.class)
public class XACMLGenerator implements XACMLGeneration {

    private ContextTypeConverter<PolicySetType, PolicySet> setHandler = new PolicySetHandler();

    @Override
    public void generateXACML(PCMBlackBoard pcm, ConfidentialAccessSpecification confidentialitySpecification,
            String path) {
        // set root policyset with description
        var set = this.setHandler.transform(confidentialitySpecification.getPolicyset());
        set.setDescription("Policies for " + pcm.getSystem().getEntityName()
                + ". Automatically created by Palladio-XACML-Integration");

        // create child policy sets
        var factory = new ObjectFactory();
        if (confidentialitySpecification.getPolicyset() != null) {
            var listChildSets = confidentialitySpecification.getPolicyset().getPolicyset().stream()
                    .map(this.setHandler::transform).map(factory::createPolicySet).collect(Collectors.toList());

            set.getPolicySetOrPolicyOrPolicySetIdReference().addAll(listChildSets);
        }

        var objectFactory = new ObjectFactory();
        var policySetElement = objectFactory.createPolicySet(set);
        XACMLPolicyWriter.writeXACMLFile(Path.of(path), policySetElement, PolicySetType.class);
    }

}
