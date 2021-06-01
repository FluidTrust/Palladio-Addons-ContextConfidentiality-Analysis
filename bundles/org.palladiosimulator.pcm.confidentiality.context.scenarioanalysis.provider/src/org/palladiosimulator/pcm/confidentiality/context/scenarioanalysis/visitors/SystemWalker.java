package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.eclipse.emf.common.util.EList;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers.PCMInstanceHelper;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.repository.Signature;
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
            final ContextSet context) {
        final var assemblyContext = this.getHandlingAssemblyContext(systemCall, system);
        final var encapsulatingContexts = new ArrayList<AssemblyContext>();
        encapsulatingContexts.add(assemblyContext);

        this.operation.performCheck(systemCall, assemblyContext, context);

        final var seff = this.getSEFF(systemCall, system);
        this.propagationBySeff(seff, encapsulatingContexts, context);
    }

    private void propagationBySeff(final ServiceEffectSpecification seff,
            final List<AssemblyContext> encapsulatingContexts, ContextSet context) {
        final var visitor2 = new SeffAssemblyContext();
        final var externalCallActions = visitor2.doSwitch(seff);
        for (final var externalAction : externalCallActions) {
            final var contextOpt = this.operation.performCheck(externalAction,
                    encapsulatingContexts.get(encapsulatingContexts.size() - 1), context);
            final var service = PCMInstanceHelper.getHandlingAssemblyContexts(externalAction, encapsulatingContexts);
            final var nextSeff = this.getSEFF(externalAction.getCalledService_ExternalService(),
                    service.get(service.size() - 1));
            if (contextOpt.isPresent()) {
                context = contextOpt.get();
            }
            this.propagationBySeff(nextSeff, service, context);
        }
    }

    private ServiceEffectSpecification getSEFF(final EntryLevelSystemCall call, final System system) {
        final Signature sig = call.getOperationSignature__EntryLevelSystemCall();

        final AssemblyContext ac = this.getHandlingAssemblyContext(call, system);
        return this.getSEFF(sig, ac);
    }

    private AssemblyContext getHandlingAssemblyContext(final EntryLevelSystemCall call, final System system) {
        final List<AssemblyContext> acList = PCMInstanceHelper.getHandlingAssemblyContexts(call, system);
        return acList.get(acList.size() - 1); // according to specification last element of list is
                                              // the actual assembly context
    }

    private ServiceEffectSpecification getSEFF(final Signature sig, final AssemblyContext ac) {
        final BasicComponent bc = (BasicComponent) ac.getEncapsulatedComponent__AssemblyContext();
        final EList<ServiceEffectSpecification> seffList = bc.getServiceEffectSpecifications__BasicComponent();
        for (final ServiceEffectSpecification seff : seffList) {
            if (seff.getDescribedService__SEFF().getEntityName().equals(sig.getEntityName())) {
                return seff;
            }
        }
        return null;
    }
}
