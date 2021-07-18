package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp;

import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.AttributeValue;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl.AttributeSwitch;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util.XACMLPolicyWriter;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.Evaluate;

import com.att.research.xacml.api.Decision;
import com.att.research.xacml.api.XACML3;
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

    private ObjectFactory factory = new ObjectFactory();

    @Override
    public boolean evaluate(List<UsageSpecification> subject, List<UsageSpecification> environment,
            List<UsageSpecification> resource, List<UsageSpecification> operation) {

        var request = this.factory.createRequestType();

        request.getAttributes().add(assignAttributes(XACML3.ID_SUBJECT_CATEGORY_ACCESS_SUBJECT.stringValue(), subject));
        request.getAttributes()
                .add(assignAttributes(XACML3.ID_ATTRIBUTE_CATEGORY_ENVIRONMENT.stringValue(), environment));
        request.getAttributes().add(assignAttributes(XACML3.ID_ATTRIBUTE_CATEGORY_RESOURCE.stringValue(), resource));
        request.getAttributes().add(assignAttributes(XACML3.ID_ATTRIBUTE_CATEGORY_ACTION.stringValue(), operation));

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
        properties.put("properties.file", "/home/majuwa/tmp/test.xml");
        try {
            var engine = ATTPDPEngineFactory.newInstance().newEngine(properties);

            var requestString = XACMLPolicyWriter.createXMLString(this.factory.createRequest(request),
                    RequestType.class);
            if (requestString.isPresent()) {
                var string = requestString.get();
                var actualRequest = DOMRequest.load(string);
                var response = engine.decide(actualRequest);
                engine.shutdown();
                var decision = response.getResults().iterator().next().getDecision();
                return response.getResults().iterator().next().getDecision().equals(Decision.PERMIT);

            }

        } catch (FactoryException e) {
            e.printStackTrace();
        } catch (PDPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (DOMStructureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return false;
    }

    private AttributesType assignAttributes(String category, List<UsageSpecification> attributeValues) {
        var attributes = this.factory.createAttributesType();
        attributes.setCategory(category);

        attributeValues.stream().flatMap(this::convertUsage).forEach(attributes.getAttribute()::add);

        return attributes;
    }

    private Stream<AttributeType> convertUsage(UsageSpecification usageSpecification) {
        return usageSpecification.getAttributevalue().stream().map(this::convertAttributeValue);
    }

    private AttributeType convertAttributeValue(AttributeValue attributeValue) {
        var attribute = this.factory.createAttributeType();
        var attributeSwitch = new AttributeSwitch(attribute);
        attributeSwitch.doSwitch(attributeValue.eContainer());

        return attribute;
    }

}
