package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.List;
import java.util.Set;

import org.eclipse.emf.common.util.EList;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers.PCMHelpers;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers.PCMInstanceHelper;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ResourceDemandingBehaviour;
import org.palladiosimulator.pcm.seff.ServiceEffectSpecification;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;

@Deprecated
public class UsageModelVisitorScenarioRepository extends AbstractUsageModelVisitor<ResourceDemandingBehaviour>{
   
    @Override
    public Set<ResourceDemandingBehaviour> caseEntryLevelSystemCall(EntryLevelSystemCall call) {
        logger.debug("VisitEntryLevelSystemCall");
        logger.debug("Called System Method ");
             
        
        var seff = getNextSEFF(call);
        var seffVisitor = new SeffVisitorScenarioAnalysis();
        var list = seffVisitor.doSwitch(seff);
        list.addAll(doSwitch(call.getSuccessor()));
        return list;
    }
    private ServiceEffectSpecification getNextSEFF(EntryLevelSystemCall call) {
        Signature sig = call.getOperationSignature__EntryLevelSystemCall();

        List<AssemblyContext> acList = PCMInstanceHelper
                .getHandlingAssemblyContexts(call, PCMHelpers.getSystem(call));

        AssemblyContext ac = acList.get(acList.size() - 1);
        BasicComponent bc = (BasicComponent) ac
                .getEncapsulatedComponent__AssemblyContext();
        EList<ServiceEffectSpecification> seffList = bc
                .getServiceEffectSpecifications__BasicComponent();
        for (ServiceEffectSpecification seff : seffList) {
            if (seff.getDescribedService__SEFF().getEntityName().equals(
                    sig.getEntityName())) {
                return seff;
            }
        }
        return null;
    }

}
