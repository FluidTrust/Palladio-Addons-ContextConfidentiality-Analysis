package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import org.palladiosimulator.pcm.confidentiality.context.policy.Apply;
import org.palladiosimulator.pcm.confidentiality.context.policy.AttributeDesignator;
import org.palladiosimulator.pcm.confidentiality.context.policy.Expression;
import org.palladiosimulator.pcm.confidentiality.context.policy.util.PolicySwitch;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;

public class ExpressionPreCalculation extends PolicySwitch<Expression> {

    private ObjectFactory factory = new ObjectFactory();

    @Override
    public Expression caseApply(Apply object) {

//        for (var i = 0; i < object.getParameters().size(); i++) {
//            var convertedObject = doSwitch(object.getParameters().get(i));
//            if (convertedObject != null) {
//                object.getParameters().add(++i, convertedObject);
//            }
//        }

        return null;
    }

    @Override
    public Expression caseAttributeDesignator(AttributeDesignator object) {
        return null;
//        if (object.getAttributevalue() == null) {
//            return null;
//        }
//
//        var valueExpression = PolicyFactory.eINSTANCE.createAttributeValueReference();
//        valueExpression.setAttributevalue(object.getAttributevalue());
//        return valueExpression;
    }

}
