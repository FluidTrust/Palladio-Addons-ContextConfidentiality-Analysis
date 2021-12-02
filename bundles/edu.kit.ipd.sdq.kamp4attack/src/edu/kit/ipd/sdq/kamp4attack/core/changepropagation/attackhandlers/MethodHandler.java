package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class MethodHandler extends AttackHandler {

    public MethodHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }

    public void attackService(final Collection<ServiceRestriction> services, final CredentialChange change,
            final EObject source) {
        final var compromisedComponent = services.stream().map(e -> attackComponent(e, change, source))
                .flatMap(Optional::stream).collect(Collectors.toList());
        final var newCompromisedComponent = filterExsiting(compromisedComponent, change);
        if (!newCompromisedComponent.isEmpty()) {
            handleDataExtraction(newCompromisedComponent);
            change.setChanged(true);
            change.getCompromisedassembly().addAll(newCompromisedComponent);
            CollectionHelper.addService(newCompromisedComponent, getModelStorage().getVulnerabilitySpecification(),
                    change);
        }
    }

    private void handleDataExtraction(final Collection<CompromisedAssembly> components) {

        Collection<AssemblyContext> filteredComponents = components.stream()
                .map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());

        filteredComponents = CollectionHelper.removeDuplicates(filteredComponents);

        final var dataList = filteredComponents.stream().distinct()
                .flatMap(component -> DataHandler.getData(component).stream()).collect(Collectors.toList());

        getDataHandler().addData(dataList);
    }

    protected abstract Optional<CompromisedAssembly> attackComponent(ServiceRestriction component,
            CredentialChange change, EObject source);

    private Collection<CompromisedAssembly> filterExsiting(final Collection<CompromisedAssembly> components,
            final CredentialChange change) {
        return components.stream().filter(component -> !contains(component, change)).collect(Collectors.toList());

    }

    private boolean contains(final CompromisedAssembly component, final CredentialChange change) {
        return change.getCompromisedassembly().stream().anyMatch(referenceComponent -> EcoreUtil
                .equals(referenceComponent.getAffectedElement(), component.getAffectedElement()));
    }

    protected Vulnerability checkVulnerability(final ServiceRestriction entity, final CredentialChange change,
            final List<UsageSpecification> credentials, final List<Attack> attacks,
            final List<Vulnerability> vulnerabilityList, final AttackVector attackVector) {
        final var result = this.queryAccessForEntity(entity.getAssemblycontext(), credentials, entity.getSignature());
        return this.checkVulnerability(change, attacks, vulnerabilityList, attackVector, result);
    }

}
