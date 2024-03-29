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

    private final ContextTypeConverter<PolicySetType, PolicySet> setHandler = new PolicySetHandler();

    @Override
    public void generateXACML(final PCMBlackBoard pcm,
            final ConfidentialAccessSpecification confidentialitySpecification, final String path) {
        // set root policyset with description
        final var set = this.setHandler.transform(confidentialitySpecification.getPolicyset());
        set.setDescription("Policies for " + pcm.getSystem()
            .getEntityName() + ". Automatically created by Palladio-XACML-Integration");

        // create child policy sets
        final var factory = new ObjectFactory();
        if (confidentialitySpecification.getPolicyset() != null) {
            final var listChildSets = confidentialitySpecification.getPolicyset()
                .getPolicyset()
                .stream()
                .map(this.setHandler::transform)
                .map(factory::createPolicySet)
                .collect(Collectors.toList());

            set.getPolicySetOrPolicyOrPolicySetIdReference()
                .addAll(listChildSets);
        }

        final var objectFactory = new ObjectFactory();
        final var policySetElement = objectFactory.createPolicySet(set);
        XACMLPolicyWriter.writeXACMLFile(Path.of(path), policySetElement, PolicySetType.class);
    }

}
