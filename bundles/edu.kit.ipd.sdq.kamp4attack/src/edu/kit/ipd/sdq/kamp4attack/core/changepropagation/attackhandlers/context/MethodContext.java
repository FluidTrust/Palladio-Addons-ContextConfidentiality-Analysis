package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context;

import java.util.List;
import java.util.Optional;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;

import com.google.common.base.Objects;

import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.MethodHandler;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class MethodContext extends MethodHandler {

    public MethodContext(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }

    @Override
    protected Optional<CompromisedAssembly> attackEntity(final ServiceSpecification service,
            final CredentialChange change, final EObject source) {
        final List<? extends UsageSpecification> credentials = this.getCredentials(change);

        final var serviceModel = CollectionHelper.findOrCreateServiceSpecification(service, this.getModelStorage()
            .getVulnerabilitySpecification(), change);
        final var result = this.queryAccessForEntity(serviceModel.getAssemblycontext(), credentials,
                serviceModel.getSignature());

        if (result.isPresent() && Objects.equal(result.get()
            .decision(), DecisionType.PERMIT)) {
            final var sourceList = this.createSource(source, credentials);

            final var compromised = HelperCreationCompromisedElements.createCompromisedService(serviceModel,
                    sourceList);
            final var serviceRestrictions = CollectionHelper.filterExistingService(List.of(compromised), change);
            if (!serviceRestrictions.isEmpty()) {
                change.getCompromisedservice()
                    .addAll(serviceRestrictions);
                change.setChanged(true);

                // TODO think about parameter handling e.g. only access is granted but data of
                // parametes
                // is usally not compromised. Return value might

                serviceRestrictions.stream()
                    .map(CompromisedService::getAffectedElement)
                    .map(DataHandler::getData)
                    .forEach(this.getDataHandler()::addData);
            }

//            var data = DataHandler.getData(service);
//            getDataHandler().addData(data);
        }

        return Optional.empty();
    }

}
