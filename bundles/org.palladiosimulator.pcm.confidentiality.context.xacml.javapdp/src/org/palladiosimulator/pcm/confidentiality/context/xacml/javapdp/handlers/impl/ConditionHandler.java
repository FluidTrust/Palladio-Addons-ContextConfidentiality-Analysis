package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import org.palladiosimulator.pcm.confidentiality.context.policy.Expression;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ConditionType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;

public class ConditionHandler implements ContextTypeConverter<ConditionType, Expression> {
    private final ObjectFactory factory = new ObjectFactory();

    @Override
    public ConditionType transform(final Expression inputModel) {
        final var conditionType = this.factory.createConditionType();

        final var conditionSwitch = new ExpressionSwitch();

        final var expressionType = conditionSwitch.doSwitch(inputModel);

        conditionType.setExpression(expressionType);

        return conditionType;
    }

}
