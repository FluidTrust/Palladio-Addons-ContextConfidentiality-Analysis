package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AssemblyContextHandler extends AttackHandler {

    protected AssemblyContextHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }

    public void attackAssemblyContext(final Collection<AssemblyContext> components, final CredentialChange change,
            final EObject source) {
        final var compromisedComponent = components.stream().map(e -> this.attackComponent(e, change, source))
                .flatMap(Optional::stream).collect(Collectors.toList());
        final var newCompromisedComponent = this.filterExsiting(compromisedComponent, change);
        if (!newCompromisedComponent.isEmpty()) {
            this.handleDataExtraction(newCompromisedComponent);
            change.setChanged(true);
            change.getCompromisedassembly().addAll(newCompromisedComponent);
        }
    }

    private void handleDataExtraction(final Collection<CompromisedAssembly> components) {

        Collection<AssemblyContext> filteredComponents = components.stream()
                .map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());

        filteredComponents = CollectionHelper.removeDuplicates(filteredComponents);

        final var dataList = filteredComponents.stream()
                .map(component -> component.getEncapsulatedComponent__AssemblyContext()).distinct()
                .flatMap(component -> DataHandler.getData(component).stream()).collect(Collectors.toList());

        this.getDataHandler().addData(dataList);
    }

    protected abstract Optional<CompromisedAssembly> attackComponent(AssemblyContext component, CredentialChange change,
            EObject source);

    private Collection<CompromisedAssembly> filterExsiting(final Collection<CompromisedAssembly> components,
            final CredentialChange change) {
        return components.stream().filter(component -> !this.contains(component, change)).collect(Collectors.toList());

    }

    private boolean contains(final CompromisedAssembly component, final CredentialChange change) {
        return change.getCompromisedassembly().stream().anyMatch(referenceComponent -> EcoreUtil
                .equals(referenceComponent.getAffectedElement(), component.getAffectedElement()));
    }

}
