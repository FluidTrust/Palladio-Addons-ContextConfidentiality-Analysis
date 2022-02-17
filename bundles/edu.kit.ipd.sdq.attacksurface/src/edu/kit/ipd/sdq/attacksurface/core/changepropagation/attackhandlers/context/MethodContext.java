package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;

import com.google.common.base.Objects;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.MethodHandler;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.CVSurface;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialSurface;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class MethodContext extends MethodHandler {

    public MethodContext(BlackboardWrapper modelStorage, DataHandlerAttacker dataHandler, 
            final AttackGraph attackGraph) {
        super(modelStorage, dataHandler, attackGraph);
    }

    @Override
    protected Optional<CompromisedAssembly> attackComponent(ServiceRestriction service, CredentialChange change,
            EObject source) {
        final List<? extends UsageSpecification> credentials = getCredentials(change);

        var serviceModel = CollectionHelper.findOrCreateServiceRestriction(service,
                getModelStorage().getVulnerabilitySpecification(), change);
        final var result = this.queryAccessForEntity(serviceModel.getAssemblycontext(), credentials,
                serviceModel.getSignature());

        if (result.isPresent() && Objects.equal(result.get().getDecision(), DecisionType.PERMIT)) {
            final var sourceList = createSource(source, credentials);

            final var compromised = HelperCreationCompromisedElements.createCompromisedService(serviceModel,
                    sourceList);
            var serviceRestrictions = CollectionHelper.filterExistingService(List.of(compromised), change);
            if (!serviceRestrictions.isEmpty()) {
                //change.getCompromisedservice().addAll(serviceRestrictions);
                //TODO ^ remove and adapt
                change.setChanged(true);
            }

            // TODO think about parameter handling e.g. only access is granted but data of parametes
            // is usally not compromised. Return value might
            //            var data = DataHandler.getData(service.getService());
            //            getDataHandler().addData(data);
        }

        return Optional.empty();
    }

    @Override
    protected Set<String> getCauses(EList<EObject> causingElements) {
        // TODO Auto-generated method stub
        return null; //TODO adapt
    }

    @Override
    protected Function<String, CVSurface> getSurfaceMapper() {
        return CredentialSurface::new;
    }

}
