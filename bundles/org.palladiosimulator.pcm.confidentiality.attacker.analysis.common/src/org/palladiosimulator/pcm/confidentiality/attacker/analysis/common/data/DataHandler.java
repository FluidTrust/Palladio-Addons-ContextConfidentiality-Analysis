package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.PCMInstanceHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.repository.OperationSignature;
import org.palladiosimulator.pcm.repository.Parameter;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.seff.ExternalCallAction;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;

public class DataHandler {

    private DataHandler() {

    }

    public static Collection<DatamodelAttacker> getData(final AssemblyContext assemblyContext) {

        var component = (BasicComponent) assemblyContext.getEncapsulatedComponent__AssemblyContext();

        var dataList = component.getServiceEffectSpecifications__BasicComponent().stream()
                .filter(ResourceDemandingSEFF.class::isInstance).map(ResourceDemandingSEFF.class::cast)
                .flatMap(seff -> getData(seff, assemblyContext).stream()).collect(Collectors.toList());

        dataList.stream().forEach(data -> data.setSource(assemblyContext));
        return dataList;

    }

    private static Optional<DatamodelAttacker> createDataReturnValue(final OperationSignature signature,
            List<AssemblyContext> context) {
        // TODO: consider external call see above
        if (signature.getReturnType__OperationSignature() == null) {
            return Optional.empty();
        }
        final var data = AttackerFactory.eINSTANCE.createDatamodelAttacker();
        data.setDataType(signature.getReturnType__OperationSignature());
        data.setMethod(signature);
        data.getContext().addAll(context);
        return Optional.of(data);
    }

    private static Collection<DatamodelAttacker> createDataFromParameter(final Stream<Parameter> parameters,
            List<AssemblyContext> context) {
        return parameters.map(parameter -> {
            final var data = AttackerFactory.eINSTANCE.createDatamodelAttacker();
            data.setDataType(parameter.getDataType__Parameter());
            data.setReferenceName(parameter.getParameterName());
            data.setMethod(parameter.getOperationSignature__Parameter());
            data.getContext().addAll(context);
            return data;
        }).collect(Collectors.toList());
    }

    public static List<DatamodelAttacker> getData(final ResourceContainer resource, final Allocation allocation) {
        final var assemblyContexts = CollectionHelper.getAssemblyContext(List.of(resource), allocation);
        return assemblyContexts.stream().flatMap(e -> getData(e).stream()).collect(Collectors.toList());
    }

    public static Collection<DatamodelAttacker> getData(ServiceRestriction serviceRestriction) {
        var dataList = getData(serviceRestriction.getService(), serviceRestriction.getAssemblycontext());
        dataList.stream().forEach(data -> data.setSource(serviceRestriction));
        return dataList;
    }

    private static Collection<DatamodelAttacker> getData(final ResourceDemandingSEFF seff, AssemblyContext context) {
        final var parameterStream = ((OperationSignature) seff.getDescribedService__SEFF())
                .getParameters__OperationSignature().stream();

        final var dataSignatureList = DataHandler.createDataFromParameter(parameterStream, List.of(context));
        createDataReturnValue((OperationSignature) seff.getDescribedService__SEFF(), List.of(context))
                .ifPresent(dataSignatureList::add);

        var seffList = getExternalData(seff, context);
        dataSignatureList.addAll(seffList);
        return dataSignatureList;

    }

    private static Collection<DatamodelAttacker> getExternalData(final ResourceDemandingSEFF seff,
            AssemblyContext source) {
        return seff.getSteps_Behaviour().stream().filter(ExternalCallAction.class::isInstance)
                .map(ExternalCallAction.class::cast).flatMap(action -> {

                    var context = PCMInstanceHelper.getHandlingAssemblyContexts(action, List.of(source));
                    var targetOperation = action.getCalledService_ExternalService();

                    var parameters = getParameters(List.of(targetOperation));

                    var data = createDataFromParameter(parameters, context);

                    createDataReturnValue(targetOperation, context).ifPresent(data::add);
                    return data.stream();
                }).collect(Collectors.toList());

    }

    private static Stream<Parameter> getParameters(Collection<OperationSignature> signatures) {
        return signatures.stream().flatMap(signature -> signature.getParameters__OperationSignature().stream());

    }

}
