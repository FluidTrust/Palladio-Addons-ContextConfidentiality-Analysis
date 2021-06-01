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
public class UsageModelVisitorScenarioRepository extends AbstractUsageModelVisitor<ResourceDemandingBehaviour> {

    @Override
    public Set<ResourceDemandingBehaviour> caseEntryLevelSystemCall(final EntryLevelSystemCall call) {
        logger.debug("VisitEntryLevelSystemCall");
        logger.debug("Called System Method ");

        final var seff = this.getNextSEFF(call);
        final var seffVisitor = new SeffVisitorScenarioAnalysis();
        final var list = seffVisitor.doSwitch(seff);
        list.addAll(this.doSwitch(call.getSuccessor()));
        return list;
    }

    private ServiceEffectSpecification getNextSEFF(final EntryLevelSystemCall call) {
        final Signature sig = call.getOperationSignature__EntryLevelSystemCall();

        final List<AssemblyContext> acList = PCMInstanceHelper.getHandlingAssemblyContexts(call,
                PCMHelpers.getSystem(call));

        final AssemblyContext ac = acList.get(acList.size() - 1);
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
