package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.io.StringReader;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import org.palladiosimulator.pcm.confidentiality.context.policy.Apply;
import org.palladiosimulator.pcm.confidentiality.context.policy.AttributeDesignator;
import org.palladiosimulator.pcm.confidentiality.context.policy.AttributeValueReference;
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

    private final ObjectFactory factory = new ObjectFactory();
    private static final Logger LOGGER = Logger.getLogger(ExpressionSwitch.class.getName());

    @Override
    public JAXBElement<? extends ExpressionType> caseApply(final Apply object) {
        final var applyType = this.factory.createApplyType();
        applyType.setDescription(object.getEntityName());

        object.getParameters()
            .stream()
            .map(this::doSwitch)
            .forEach(applyType.getExpression()::add);
        EnumHelpers.extractAndSetFunction(object.getOperation(), applyType::setFunctionId);
        return this.factory.createApply(applyType);
    }

    @Override
    public JAXBElement<? extends ExpressionType> caseAttributeDesignator(final AttributeDesignator object) {
        final var designator = this.factory.createAttributeDesignatorType();
        designator.setMustBePresent(object.isMustBePresent());

        EnumHelpers.extractAndSetDataType(object.getType(), designator::setDataType);
        EnumHelpers.extractAndSetCategory(object.getCategory(), designator::setCategory);

        final var attribute = object.getAttribute();
        designator.setAttributeId(attribute.getId());

        if (attribute instanceof final SystemEntityAttribute systemEntitiyAttribute) {

            designator.setIssuer(systemEntitiyAttribute.getModelEntity()
                .getId());
        }

        designator.setMustBePresent(object.isMustBePresent());

        return this.factory.createAttributeDesignator(designator);

    }

    @Override
    public JAXBElement<?> caseAttributeValueReference(final AttributeValueReference object) {
        final var attributeValue = this.factory.createAttributeValueType();
        EnumHelpers.extractAndSetDataType(object.getAttributevalue()
            .getType(), attributeValue::setDataType);
        attributeValue.getContent()
            .addAll(object.getAttributevalue()
                .getValues());

        return this.factory.createAttributeValue(attributeValue);

    }

    @Override
    public JAXBElement<?> caseFunctionReference(final FunctionReference object) {
        final var functionReference = this.factory.createFunctionType();

        EnumHelpers.extractAndSetFunction(object.getFunction(), functionReference::setFunctionId);

        return this.factory.createFunction(functionReference);

    }

    @Override
    public JAXBElement<?> caseVariableReference(final VariableReference object) {
        final var variableReference = this.factory.createVariableReferenceType();
        variableReference.setVariableId(object.getVariabledefinitions()
            .getId());
        return this.factory.createVariableReference(variableReference);

    }

    @Override
    public JAXBElement<?> caseXMLString(final XMLString object) {
        try {
            final var context = ContextFactory.createContext(new Class[] { ExpressionType.class }, null);
            final var unmarshall = context.createUnmarshaller();
            final var privateObject = unmarshall.unmarshal(new StringReader(object.getString()));
            return (JAXBElement<?>) privateObject;

        } catch (final JAXBException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());

        }
        return null;

    }

    @Override
    public JAXBElement<?> caseSimpleAttributeCondition(final SimpleAttributeCondition object) {
        final var applyObject = PolicyFactory.eINSTANCE.createApply();
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

        final var functionReference = PolicyFactory.eINSTANCE.createFunctionReference();
        functionReference.setFunction(Operations.STRING_EQUAL);
        applyObject.getParameters()
            .add(functionReference);

        final var valueReference = PolicyFactory.eINSTANCE.createAttributeValueReference();
        valueReference.setAttributevalue(object.getAttribute()
            .getAttributevalue());
        applyObject.getParameters()
            .add(valueReference);

        final var selector = PolicyFactory.eINSTANCE.createAttributeDesignator();
        selector.setCategory(object.getCategory());
        selector.setAttribute(object.getAttribute()
            .getAttribute());

        applyObject.getParameters()
            .add(selector);

        return this.caseApply(applyObject);
    }

}
