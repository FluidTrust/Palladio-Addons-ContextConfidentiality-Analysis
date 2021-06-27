package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers;

public interface ContextTypeConverter<T, E> {

    T transform(E inputModel);

}
