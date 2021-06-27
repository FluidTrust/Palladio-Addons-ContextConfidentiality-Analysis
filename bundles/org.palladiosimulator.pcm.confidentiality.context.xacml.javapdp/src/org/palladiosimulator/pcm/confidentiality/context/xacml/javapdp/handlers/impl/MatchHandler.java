package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.util.List;
import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.context.policy.Match;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ComponentMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.GenericMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.util.StructureSwitch;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import com.att.research.xacml.api.XACML3;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.MatchType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;

@Component(service = MatchHandler.class)
public class MatchHandler implements ContextTypeConverter<List<MatchType>, List<Match>> {

    @Override
    public List<MatchType> transform(List<Match> inputModel) {
        final var factory = new ObjectFactory();

        var switchMatch = new StructureSwitch<MatchType>() {
            @Override
            public MatchType caseComponentMatch(ComponentMatch match) {

                return null;

            }

            @Override
            public MatchType caseGenericMatch(GenericMatch object) {
                final var matchType = factory.createMatchType();
                matchType.setMatchId(object.getId());
                var designator = factory.createAttributeDesignatorType();
                var value = factory.createAttributeValueType();
                switch (object.getCategory()) {
                case ENVIRONMENT:
                    designator.setCategory(XACML3.ID_ATTRIBUTE_CATEGORY_ENVIRONMENT.toString());
                    break;
                case RESOURCE:
                    designator.setCategory(XACML3.ID_ATTRIBUTE_CATEGORY_RESOURCE.toString());
                    break;
                case SUBJECT:
                    designator.setCategory(XACML3.ID_SUBJECT.toString());
                    break;
                default:
                    throw new IllegalStateException("Unkonw Attribute Category");
                }

                switch (object.getAttributevalue().getType()) {
                case BOOLEAN:
                    designator.setDataType(XACML3.ID_DATATYPE_BOOLEAN.stringValue());
                    value.setDataType(XACML3.ID_DATATYPE_BOOLEAN.stringValue());
                    break;
                case DATE:
                    designator.setDataType(XACML3.ID_DATATYPE_DATE.stringValue());
                    value.setDataType(XACML3.ID_DATATYPE_DATE.stringValue());
                    break;
                case DOUBLE:
                    designator.setDataType(XACML3.ID_DATATYPE_DOUBLE.stringValue());
                    value.setDataType(XACML3.ID_DATATYPE_DOUBLE.stringValue());
                    break;
                case INTEGER:
                    designator.setDataType(XACML3.ID_DATATYPE_INTEGER.stringValue());
                    value.setDataType(XACML3.ID_DATATYPE_INTEGER.stringValue());
                    break;
                case STRING:
                    designator.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                    value.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                    break;
                default:
                    throw new IllegalStateException("Unkonw Datatype");
                }

                switch (object.getOperation()) {
                case EQUALS:
                    matchType.setMatchId(XACML3.ID_FUNCTION_STRING_EQUAL.stringValue());
                    break;
                default:
                    break;

                }

                value.getContent().add(object.getAttributevalue().getValue());

                matchType.setAttributeValue(value);
                return matchType;

            }

        };

        return inputModel.stream().map(switchMatch::doSwitch).collect(Collectors.toList());

    }

}
