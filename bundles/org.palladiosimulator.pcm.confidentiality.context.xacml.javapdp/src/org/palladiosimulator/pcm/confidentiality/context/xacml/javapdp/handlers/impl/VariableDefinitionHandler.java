package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.util.List;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.context.policy.VariableDefinitions;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.VariableDefinitionType;


public class VariableDefinitionHandler
implements ContextTypeConverter<List<VariableDefinitionType>, List<VariableDefinitions>> {

    private ObjectFactory factory = new ObjectFactory();

    @Override
    public List<VariableDefinitionType> transform(List<VariableDefinitions> inputModel) {
        return inputModel.stream().map(this::transformVariableDefinition).collect(Collectors.toList());
    }

    private VariableDefinitionType transformVariableDefinition(VariableDefinitions e) {
        var variableDefintionType = this.factory.createVariableDefinitionType();
        variableDefintionType.setVariableId(e.getId());

        var conditionSwitch = new ExpressionSwitch();
        var expressionType = conditionSwitch.doSwitch(e.getExpression());
        variableDefintionType.setExpression(expressionType);
        return variableDefintionType;
    }

}
