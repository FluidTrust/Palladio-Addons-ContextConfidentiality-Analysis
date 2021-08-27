package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import org.palladiosimulator.pcm.confidentiality.context.systemcontext.Attribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.AttributeValue;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemEntityAttribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.util.SystemcontextSwitch;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util.EnumHelpers;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributeType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;

public class AttributeSwitch extends SystemcontextSwitch<Void> {
    private AttributeType attribute;
    private AttributeValue value;

    public AttributeSwitch(AttributeType attribute, AttributeValue value) {
        this.attribute = attribute;
        this.value = value;
    }

    @Override
    public Void caseAttribute(Attribute object) {
        this.attribute.setAttributeId(object.getId());

        var valueType = new ObjectFactory().createAttributeValueType();
        valueType.getContent().addAll(this.value.getValues());
        EnumHelpers.extractAndSetDataType(this.value.getType(), valueType::setDataType);

        this.attribute.getAttributeValue().add(valueType);
        return null;
    }

    @Override
    public Void caseSystemEntityAttribute(SystemEntityAttribute object) {

        this.attribute.setIssuer(object.getModelEntity().getId());

        return null;
    }

}
