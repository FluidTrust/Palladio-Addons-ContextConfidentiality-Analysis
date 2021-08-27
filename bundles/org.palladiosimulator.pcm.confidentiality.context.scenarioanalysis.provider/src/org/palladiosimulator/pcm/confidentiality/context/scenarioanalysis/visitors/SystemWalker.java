package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers.PCMInstanceHelper;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;
import org.palladiosimulator.pcm.seff.ServiceEffectSpecification;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;

public class SystemWalker {

    private final CheckOperation operation;

    public SystemWalker(final CheckOperation operation) {
        Objects.requireNonNull(operation);
        this.operation = operation;

    }

    public void propagationBySeff(final EntryLevelSystemCall systemCall, final System system,
            final List<? extends UsageSpecification> context) {
        final var assemblyContext = getHandlingAssemblyContext(systemCall, system);
        final var encapsulatingContexts = new LinkedList<AssemblyContext>();
        encapsulatingContexts.add(assemblyContext);

        final var seff = this.getSEFF(systemCall, system);

        this.operation.performCheck(seff.getDescribedService__SEFF(), encapsulatingContexts, seff, context);

        this.propagationBySeff(seff, encapsulatingContexts, context);
    }

    private void propagationBySeff(final ServiceEffectSpecification seff,
            final LinkedList<AssemblyContext> encapsulatingContexts, List<? extends UsageSpecification> context) {
        final var visitor2 = new SeffAssemblyContext();
        final var externalCallActions = visitor2.doSwitch(seff);
        for (final var externalAction : externalCallActions) {
            final var service = new LinkedList<>(
                    PCMInstanceHelper.getHandlingAssemblyContexts(externalAction, encapsulatingContexts));
            final var nextSeff = this.getSEFF(externalAction.getCalledService_ExternalService(),
                    service.get(service.size() - 1));
            this.operation.performCheck(nextSeff.getDescribedService__SEFF(), service, nextSeff, context);
            //            if (contextOpt.isPresent()) {
            //                context = contextOpt.get();
            //            }
            this.propagationBySeff(nextSeff, service, context);
        }
    }

    private ResourceDemandingSEFF getSEFF(final EntryLevelSystemCall call, final System system) {
        final Signature sig = call.getOperationSignature__EntryLevelSystemCall();

        final var ac = getHandlingAssemblyContext(call, system);
        return this.getSEFF(sig, ac);
    }

    private AssemblyContext getHandlingAssemblyContext(final EntryLevelSystemCall call, final System system) {
        final var acList = PCMInstanceHelper.getHandlingAssemblyContexts(call, system);
        return acList.get(acList.size() - 1); // according to specification last element of list is
        // the actual assembly context
    }

    private ResourceDemandingSEFF getSEFF(final Signature sig, final AssemblyContext ac) {
        final var bc = (BasicComponent) ac.getEncapsulatedComponent__AssemblyContext();
        final var seffList = bc.getServiceEffectSpecifications__BasicComponent();
        for (final ServiceEffectSpecification seff : seffList) {
            if (seff.getDescribedService__SEFF().getEntityName().equals(sig.getEntityName())) {
                return (ResourceDemandingSEFF) seff;
            }
        }
        return null;
    }
}
