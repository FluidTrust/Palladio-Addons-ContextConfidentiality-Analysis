package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util;

import java.util.function.Consumer;

import org.palladiosimulator.pcm.confidentiality.context.policy.Category;
import org.palladiosimulator.pcm.confidentiality.context.policy.Operations;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.DataTypes;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl.OperationHandler;

import com.att.research.xacml.api.XACML3;

public class EnumHelpers {

    private EnumHelpers() {

    }

    public static void extractAndSetCategory(Category object, Consumer<String> assign) {
        switch (object) {
        case ENVIRONMENT:
            assign.accept(XACML3.ID_ATTRIBUTE_CATEGORY_ENVIRONMENT.toString());
            break;
        case RESOURCE:
            assign.accept(XACML3.ID_ATTRIBUTE_CATEGORY_RESOURCE.toString());
            break;
        case SUBJECT:
            assign.accept(XACML3.ID_SUBJECT.toString());
            break;
        case ACTION:
            assign.accept(XACML3.ID_ATTRIBUTE_CATEGORY_ACTION.toString());
            break;
        default:
            throw new IllegalStateException("Unkonw Attribute Category: " + object);
        }
    }

    public static void extractAndSetDataType(DataTypes object, Consumer<String> consumer) {
        switch (object) {
        case BOOLEAN:
            consumer.accept(XACML3.ID_DATATYPE_BOOLEAN.stringValue());
            break;
        case DATE:
            consumer.accept(XACML3.ID_DATATYPE_DATE.stringValue());
            break;
        case DOUBLE:
            consumer.accept(XACML3.ID_DATATYPE_DOUBLE.stringValue());
            break;
        case INTEGER:
            consumer.accept(XACML3.ID_DATATYPE_INTEGER.stringValue());
            break;
        case STRING:
            consumer.accept(XACML3.ID_DATATYPE_STRING.stringValue());
            break;
        default:
            throw new IllegalStateException("Unkonw Datatype: " + object);
        }
    }

    public static void extractAndSetFunction(Operations operation, Consumer<String> consumer) {
        var operationHandler = new OperationHandler();
        consumer.accept(operationHandler.transform(operation));

    }

}
