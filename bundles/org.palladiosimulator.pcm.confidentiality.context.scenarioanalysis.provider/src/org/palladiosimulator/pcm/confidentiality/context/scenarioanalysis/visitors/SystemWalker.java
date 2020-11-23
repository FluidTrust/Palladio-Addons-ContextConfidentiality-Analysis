package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.eclipse.emf.common.util.EList;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ServiceEffectSpecification;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;
import org.palladiosimulator.solver.transformations.PCMInstanceHelper;

public class SystemWalker {

    private CheckOperation operation;

    public SystemWalker(CheckOperation operation) {
        Objects.requireNonNull(operation);
        this.operation = operation;

    }

    public void propagationBySeff(EntryLevelSystemCall systemCall, System system) {
        var assemblyContext = getHandlingAssemblyContext(systemCall, system);
        var encapsulatingContexts = new ArrayList<AssemblyContext>();
        encapsulatingContexts.add(assemblyContext);

        operation.performCheck(systemCall, assemblyContext);

        var seff = getSEFF(systemCall, system);
        propagationBySeff(seff, encapsulatingContexts);
    }

    private void propagationBySeff(ServiceEffectSpecification seff, List<AssemblyContext> encapsulatingContexts) {
        var visitor2 = new SeffAssemblyContext();
        var externalCallActions = visitor2.doSwitch(seff);
        for (var externalAction : externalCallActions) {
            operation.performCheck(externalAction, encapsulatingContexts.get(encapsulatingContexts.size() - 1));
            var service = PCMInstanceHelper.getHandlingAssemblyContexts(externalAction, encapsulatingContexts);
            var nextSeff = getSEFF(externalAction.getCalledService_ExternalService(), service.get(service.size() - 1));
            propagationBySeff(nextSeff,service);
        }
    }

    private ServiceEffectSpecification getSEFF(EntryLevelSystemCall call, System system) {
        Signature sig = call.getOperationSignature__EntryLevelSystemCall();

        AssemblyContext ac = getHandlingAssemblyContext(call, system);
        return getSEFF(sig, ac);
    }

    private AssemblyContext getHandlingAssemblyContext(EntryLevelSystemCall call, System system) {
        List<AssemblyContext> acList = PCMInstanceHelper.getHandlingAssemblyContexts(call, system);
        return acList.get(acList.size() - 1); // according to specification last element of list is
                                              // the actual assembly context
    }

    private ServiceEffectSpecification getSEFF(Signature sig, AssemblyContext ac) {
        BasicComponent bc = (BasicComponent) ac.getEncapsulatedComponent__AssemblyContext();
        EList<ServiceEffectSpecification> seffList = bc.getServiceEffectSpecifications__BasicComponent();
        for (ServiceEffectSpecification seff : seffList) {
            if (seff.getDescribedService__SEFF().getEntityName().equals(sig.getEntityName())) {
                return seff;
            }
        }
        return null;
    }
}
