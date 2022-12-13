package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import org.palladiosimulator.pcm.confidentiality.context.systemcontext.Attribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.AttributeValue;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemEntityAttribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.util.SystemcontextSwitch;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util.EnumHelpers;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributeType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;

public class AttributeSwitch extends SystemcontextSwitch<Void> {
    private final AttributeType attribute;
    private final AttributeValue value;

    public AttributeSwitch(final AttributeType attribute, final AttributeValue value) {
        this.attribute = attribute;
        this.value = value;
    }

    @Override
    public Void caseAttribute(final Attribute object) {
        this.attribute.setAttributeId(object.getId());

        final var valueType = new ObjectFactory().createAttributeValueType();
        valueType.getContent()
            .addAll(this.value.getValues());
        EnumHelpers.extractAndSetDataType(this.value.getType(), valueType::setDataType);

        this.attribute.getAttributeValue()
            .add(valueType);
        return null;
    }

    @Override
    public Void caseSystemEntityAttribute(final SystemEntityAttribute object) {

        this.attribute.setIssuer(object.getModelEntity()
            .getId());

        return null;
    }

}
