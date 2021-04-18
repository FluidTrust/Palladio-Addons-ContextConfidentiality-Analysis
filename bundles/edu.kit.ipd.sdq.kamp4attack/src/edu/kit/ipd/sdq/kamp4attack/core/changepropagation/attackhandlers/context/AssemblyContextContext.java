package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context;

import java.util.List;
import java.util.Optional;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.helper.PolicyHelper;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.HelperCreationCompromisedElements;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class AssemblyContextContext extends AssemblyContextHandler {

    public AssemblyContextContext(BlackboardWrapper modelStorage, DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }

    @Override
    protected Optional<CompromisedAssembly> attackComponent(AssemblyContext component, CredentialChange change,
            EObject source) {
        var credentials = this.getCredentials(change);
        var policies = PolicyHelper.getPolicy(this.getModelStorage().getSpecification(), component);
        
        if (policies.stream().anyMatch(policy -> policy.checkAccessRight(credentials))) {
            var compromised = HelperCreationCompromisedElements.createCompromisedAssembly(component, List.of(source, credentials));
            return Optional.of(compromised);
        }
        return Optional.empty();
    }

}
