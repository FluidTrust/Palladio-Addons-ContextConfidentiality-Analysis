package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl.AttributeSwitch;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util.XACMLPolicyWriter;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.Evaluate;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;

import com.att.research.xacml.api.XACML3;
import com.att.research.xacml.api.pdp.PDPEngine;
import com.att.research.xacml.api.pdp.PDPException;
import com.att.research.xacml.std.dom.DOMRequest;
import com.att.research.xacml.std.dom.DOMStructureException;
import com.att.research.xacml.util.FactoryException;
import com.att.research.xacmlatt.pdp.ATTPDPEngineFactory;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributeType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributesType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.RequestType;

@Component(service = Evaluate.class)
public class XACMLPDP implements Evaluate {

    private static final Logger LOGGER = Logger.getLogger(XACMLPolicyWriter.class.getName());
    private ObjectFactory factory = new ObjectFactory();

    private Map<String, PDPResult> cache = new HashMap<>();

    private PDPEngine engine;

    @Override
    public Optional<PDPResult> evaluate(List<UsageSpecification> subject, List<UsageSpecification> environment,
            List<UsageSpecification> resource, List<UsageSpecification> operation,
            List<UsageSpecification> xacmlAttribute) {
        if (this.engine == null) {
            throw new IllegalStateException("Engine not initialized");
        }

        var request = this.factory.createRequestType();
        request.setReturnPolicyIdList(true);

        request.getAttributes().add(assignAttributes(XACML3.ID_SUBJECT.stringValue(), subject));
        request.getAttributes()
        .add(assignAttributes(XACML3.ID_ATTRIBUTE_CATEGORY_ENVIRONMENT.stringValue(), environment));
        request.getAttributes().add(assignAttributes(XACML3.ID_ATTRIBUTE_CATEGORY_RESOURCE.stringValue(), resource));
        request.getAttributes().add(assignAttributes(XACML3.ID_ATTRIBUTE_CATEGORY_ACTION.stringValue(), operation));
        try {

            var requestString = XACMLPolicyWriter.createXMLString(this.factory.createRequest(request),
                    RequestType.class);
            if (requestString.isPresent()) {
                var string = requestString.get();
                if (this.cache.containsKey(string)) {
                    return Optional.of(this.cache.get(string));
                }
                var actualRequest = DOMRequest.load(string);
                var response = this.engine.decide(actualRequest);

                if (response.getResults().size() != 1) {
                    throw new IllegalStateException("Unexpected Result Amount");
                }
                var result = response.getResults().iterator().next();

                var listPolicyID = result.getPolicyIdentifiers().stream().map(Object::toString)
                        .collect(Collectors.toList());

                DecisionType decision;
                switch (result.getDecision()) {
                case DENY:
                    decision = DecisionType.DENY;
                    break;
                case INDETERMINATE:

                case INDETERMINATE_DENY:

                case INDETERMINATE_DENYPERMIT:

                case INDETERMINATE_PERMIT:
                    decision = DecisionType.INDETERMINATE;
                    break;
                case NOTAPPLICABLE:
                    decision = DecisionType.NOT_APPLICABLE;
                    break;
                case PERMIT:
                    decision = DecisionType.PERMIT;
                    break;
                default:
                    throw new IllegalStateException("Unknown Decision type");
                }

                var resultWrapper = new PDPResult(decision, listPolicyID);
                this.cache.put(string, resultWrapper);
                return Optional.of(resultWrapper);

            }

        } catch (PDPException | DOMStructureException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());
        }

        return Optional.empty();
    }

    private AttributesType assignAttributes(String category, List<UsageSpecification> attributeValues) {
        var attributes = this.factory.createAttributesType();
        attributes.setCategory(category);

        attributeValues.stream().map(this::convertUsage).forEach(attributes.getAttribute()::add);

        return attributes;
    }

    private AttributeType convertUsage(UsageSpecification usageSpecification) {

        var attribute = this.factory.createAttributeType();
        var attributeSwitch = new AttributeSwitch(attribute, usageSpecification.getAttributevalue());
        attributeSwitch.doSwitch(usageSpecification.getAttribute());
        return attribute;
    }

    @Override
    public boolean initialize(String pathXACMLFile) {
        var properties = new Properties();
        properties.put("xacml.dataTypeFactory", "com.att.research.xacml.std.StdDataTypeFactory");
        properties.put("xacml.pdpEngineFactory", "com.att.research.xacmlatt.pdp.ATTPDPEngineFactory");
        properties.put("xacml.pepEngineFactory", "com.att.research.xacml.std.pep.StdEngineFactory");
        properties.put("xacml.pipFinderFactory", "com.att.research.xacml.std.pip.StdPIPFinderFactory");
        properties.put("xacml.att.evaluationContextFactory",
                "com.att.research.xacmlatt.pdp.std.StdEvaluationContextFactory");
        properties.put("xacml.att.combiningAlgorithmFactory",
                "com.att.research.xacmlatt.pdp.std.StdCombiningAlgorithmFactory");
        properties.put("xacml.att.functionDefinitionFactory",
                "com.att.research.xacmlatt.pdp.std.StdFunctionDefinitionFactory");
        properties.put("xacml.att.policyFinderFactory", "com.att.research.xacmlatt.pdp.std.StdPolicyFinderFactory");
        properties.put("xacml.att.stdPolicyFinderFactory.rootPolicyFile", "properties");
        properties.put("xacml.rootPolicies", "properties");
        properties.put("xacml.referencedPolicies", "properties");
        properties.put("properties.file", pathXACMLFile);

        try {
            this.engine = ATTPDPEngineFactory.newInstance().newEngine(properties);
        } catch (FactoryException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());
            return false;
        }

        return true;
    }

    @Override
    public void shutdown() {
        if (this.engine == null) {
            throw new IllegalStateException("Engine not correctly initialized. Shutdown not possible");
        }
        this.engine.shutdown();
        this.engine = null;
    }

}
