package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.util.List;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.context.policy.VariableDefinitions;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.VariableDefinitionType;

public class VariableDefinitionHandler
        implements ContextTypeConverter<List<VariableDefinitionType>, List<VariableDefinitions>> {

    private final ObjectFactory factory = new ObjectFactory();

    @Override
    public List<VariableDefinitionType> transform(final List<VariableDefinitions> inputModel) {
        return inputModel.stream().map(this::transformVariableDefinition).collect(Collectors.toList());
    }

    private VariableDefinitionType transformVariableDefinition(final VariableDefinitions e) {
        final var variableDefintionType = this.factory.createVariableDefinitionType();
        variableDefintionType.setVariableId(e.getId());

        final var conditionSwitch = new ExpressionSwitch();
        final var expressionType = conditionSwitch.doSwitch(e.getExpression());
        variableDefintionType.setExpression(expressionType);
        return variableDefintionType;
    }

}
