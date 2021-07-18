package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import org.palladiosimulator.pcm.confidentiality.context.systemcontext.Attribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemEntityAttribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.util.SystemcontextSwitch;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util.EnumHelpers;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributeType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;

public class AttributeSwitch extends SystemcontextSwitch<Void> {
    private AttributeType attribute;

    public AttributeSwitch(AttributeType attribute) {
        this.attribute = attribute;
    }

    @Override
    public Void caseAttribute(Attribute object) {
        this.attribute.setAttributeId(object.getId());

        object.getAttributevalue().stream().map(value -> {
            var valueType = new ObjectFactory().createAttributeValueType();
            valueType.getContent().add(value.getValue());
            EnumHelpers.extractAndSetDataType(value.getType(), valueType::setDataType);
            return valueType;
        }).forEach(this.attribute.getAttributeValue()::add);
        return null;
    }

    @Override
    public Void caseSystemEntityAttribute(SystemEntityAttribute object) {

        this.attribute.setIssuer(object.getModelEntity().getId());

        return null;
    }

}
