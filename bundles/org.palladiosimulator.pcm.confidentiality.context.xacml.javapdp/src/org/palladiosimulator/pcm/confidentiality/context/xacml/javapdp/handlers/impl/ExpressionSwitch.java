package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.io.StringReader;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import org.palladiosimulator.pcm.confidentiality.context.policy.Apply;
import org.palladiosimulator.pcm.confidentiality.context.policy.AttributeDesignator;
import org.palladiosimulator.pcm.confidentiality.context.policy.AttributeValueReference;
import org.palladiosimulator.pcm.confidentiality.context.policy.Category;
import org.palladiosimulator.pcm.confidentiality.context.policy.FunctionReference;
import org.palladiosimulator.pcm.confidentiality.context.policy.Operations;
import org.palladiosimulator.pcm.confidentiality.context.policy.PolicyFactory;
import org.palladiosimulator.pcm.confidentiality.context.policy.SimpleAttributeCondition;
import org.palladiosimulator.pcm.confidentiality.context.policy.VariableReference;
import org.palladiosimulator.pcm.confidentiality.context.policy.XMLString;
import org.palladiosimulator.pcm.confidentiality.context.policy.util.PolicySwitch;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemEntityAttribute;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util.EnumHelpers;

import com.sun.xml.bind.v2.ContextFactory;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ExpressionType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;

public class ExpressionSwitch extends PolicySwitch<JAXBElement<?>> {

    private ObjectFactory factory = new ObjectFactory();
    private static final Logger LOGGER = Logger.getLogger(ExpressionSwitch.class.getName());

    @Override
    public JAXBElement<? extends ExpressionType> caseApply(Apply object) {
        var applyType = this.factory.createApplyType();
        applyType.setDescription(object.getEntityName());

        object.getParameters().stream().map(this::doSwitch).forEach(applyType.getExpression()::add);
        EnumHelpers.extractAndSetFunction(object.getOperation(), applyType::setFunctionId);
        return this.factory.createApply(applyType);
    }

    @Override
    public JAXBElement<? extends ExpressionType> caseAttributeDesignator(AttributeDesignator object) {
        var designator = this.factory.createAttributeDesignatorType();
        designator.setMustBePresent(object.isMustBePresent());

        EnumHelpers.extractAndSetDataType(object.getType(), designator::setDataType);
        EnumHelpers.extractAndSetCategory(object.getCategory(), designator::setCategory);

        var attribute = object.getAttribute();
        designator.setAttributeId(attribute.getId());

        if (attribute instanceof SystemEntityAttribute) {
            designator.setIssuer(attribute.getId());
        }

        designator.setMustBePresent(object.isMustBePresent());

        return this.factory.createAttributeDesignator(designator);

    }

    @Override
    public JAXBElement<?> caseAttributeValueReference(AttributeValueReference object) {
        var attributeValue = this.factory.createAttributeValueType();
        EnumHelpers.extractAndSetDataType(object.getAttributevalue().getType(), attributeValue::setDataType);
        attributeValue.getContent().addAll(object.getAttributevalue().getValues());

        return this.factory.createAttributeValue(attributeValue);

    }

    @Override
    public JAXBElement<?> caseFunctionReference(FunctionReference object) {
        var functionReference = this.factory.createFunctionType();

        EnumHelpers.extractAndSetFunction(object.getFunction(), functionReference::setFunctionId);

        return this.factory.createFunction(functionReference);

    }

    @Override
    public JAXBElement<?> caseVariableReference(VariableReference object) {
        var variableReference = this.factory.createVariableReferenceType();
        variableReference.setVariableId(object.getVariabledefinitions().getId());
        return this.factory.createVariableReference(variableReference);

    }

    @Override
    public JAXBElement<?> caseXMLString(XMLString object) {
        try {
            var context = ContextFactory.createContext(new Class[] { ExpressionType.class }, null);
            var unmarshall = context.createUnmarshaller();
            var privateObject = unmarshall.unmarshal(new StringReader(object.getString()));
            return (JAXBElement<?>) privateObject;

        } catch (JAXBException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());

        }
        return null;

    }

    @Override
    public JAXBElement<?> caseSimpleAttributeCondition(SimpleAttributeCondition object) {
        var applyObject = PolicyFactory.eINSTANCE.createApply();
        applyObject.setEntityName(object.getEntityName());
        applyObject.setId(object.getId() + "Apply");
        if (object.isOnly()) {
            applyObject.setOperation(Operations.ALL_OF);
        } else {
            applyObject.setOperation(Operations.ANY_OF);
        }

        // create bag comparision acording to
        // https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html#_Toc325047251
        // 1. Functionreference, 2. AttributeValue, 3. Bag of values

        var functionReference = PolicyFactory.eINSTANCE.createFunctionReference();
        functionReference.setFunction(Operations.STRING_EQUAL);
        applyObject.getParameters().add(functionReference);

        var valueReference = PolicyFactory.eINSTANCE.createAttributeValueReference();
        valueReference.setAttributevalue(object.getAttribute().getAttributevalue());
        applyObject.getParameters().add(valueReference);


        var selector = PolicyFactory.eINSTANCE.createAttributeDesignator();
        selector.setCategory(Category.SUBJECT);
        selector.setAttribute(object.getAttribute().getAttribute());



        applyObject.getParameters().add(selector);


        return caseApply(applyObject);
    }

}
