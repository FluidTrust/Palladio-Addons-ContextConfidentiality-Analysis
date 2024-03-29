package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers.AttributeProviderHandler;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers.PCMInstanceHelper;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;
import org.palladiosimulator.pcm.seff.ServiceEffectSpecification;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;

public class SystemWalker {

    private final CheckOperation operation;
    private final AttributeProviderHandler attributeHandler;

    public SystemWalker(final CheckOperation operation, final AttributeProviderHandler handler) {
        Objects.requireNonNull(operation);
        this.operation = operation;
        this.attributeHandler = handler;

    }

    public void propagationBySeff(final EntryLevelSystemCall systemCall, final System system,
            final List<? extends UsageSpecification> attributes) {
        final var assemblyContext = new LinkedList<>(PCMInstanceHelper.getHandlingAssemblyContexts(systemCall, system));
        final var connector = PCMInstanceHelper.getHandlingAssemblyConnector(systemCall, system);
        final var seff = this.getSEFF(systemCall, system);

        this.operation.performCheck(seff.getDescribedService__SEFF(), connector, assemblyContext, seff, attributes,
                null, null);

        this.propagationBySeff(seff, assemblyContext, attributes);
    }

    private void propagationBySeff(final ServiceEffectSpecification seff,
            final LinkedList<AssemblyContext> encapsulatingContexts,
            final List<? extends UsageSpecification> attributes) {
        final var visitor2 = new SeffAssemblyContext();
        final var externalCallActions = visitor2.doSwitch(seff);
        for (final var externalAction : externalCallActions) {

            // replace current attributes if necessary
            final var connector = PCMInstanceHelper.getAssemblyConnectorForExternalCall(externalAction,
                    encapsulatingContexts);
            final var tmpAttributes = this.attributeHandler.getContext(connector, encapsulatingContexts);
            final var localAttributes = tmpAttributes.isEmpty() ? attributes : tmpAttributes;

            // check whether the called services are possible
            final var handlingAssembly = new LinkedList<>(
                    PCMInstanceHelper.getHandlingAssemblyContexts(externalAction, encapsulatingContexts));
            // in case of required delegations
            if (handlingAssembly.isEmpty()) {
                continue;
            }

            final var origin = StructureFactory.eINSTANCE.createServiceSpecification();
            origin.setService((ResourceDemandingSEFF) seff);
            origin.setAssemblycontext(encapsulatingContexts.getLast());
            origin.setSignature(seff.getDescribedService__SEFF());
            if (encapsulatingContexts.size() > 1) {
                final var copy = new LinkedList<>(encapsulatingContexts);
                copy.removeLast();
                origin.getHierarchy()
                    .addAll(copy);
            }

            final var nextSeff = this.getSEFF(externalAction.getCalledService_ExternalService(),
                    handlingAssembly.get(handlingAssembly.size() - 1));
            this.operation.performCheck(nextSeff.getDescribedService__SEFF(), connector, handlingAssembly, nextSeff,
                    localAttributes, origin, externalAction);

            // recursively check services
            this.propagationBySeff(nextSeff, handlingAssembly, localAttributes);
        }
    }

    private ResourceDemandingSEFF getSEFF(final EntryLevelSystemCall call, final System system) {
        final Signature sig = call.getOperationSignature__EntryLevelSystemCall();

        final var ac = this.getHandlingAssemblyContext(call, system);
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
            if (seff.getDescribedService__SEFF()
                .getEntityName()
                .equals(sig.getEntityName())) {
                return (ResourceDemandingSEFF) seff;
            }
        }
        return null;
    }
}
