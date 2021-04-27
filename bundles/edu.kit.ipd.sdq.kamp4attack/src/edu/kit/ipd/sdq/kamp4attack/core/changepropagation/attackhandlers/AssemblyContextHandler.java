package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AssemblyContextHandler extends AttackHandler {

    protected AssemblyContextHandler(BlackboardWrapper modelStorage, DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }

    public void attackAssemblyContext(Collection<AssemblyContext> components, CredentialChange change, EObject source) {
        var compromisedComponent = components.stream().map(e -> this.attackComponent(e, change, source))
                .flatMap(Optional::stream).collect(Collectors.toList());
        var newCompromisedComponent = filterExsiting(compromisedComponent, change);
        if (!newCompromisedComponent.isEmpty()) {
            handleDataExtraction(newCompromisedComponent);
            change.setChanged(true);
            change.getCompromisedassembly().addAll(newCompromisedComponent);
        }
    }

    private void handleDataExtraction(Collection<CompromisedAssembly> components) {
        
        Collection<AssemblyContext> filteredComponents = components.stream().map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());
        
        filteredComponents = CollectionHelper.removeDuplicates(filteredComponents);
        
        var dataList = filteredComponents.stream().map(component -> component.getEncapsulatedComponent__AssemblyContext()).distinct()
                .flatMap(component -> DataHandler.getData(component).stream()).collect(Collectors.toList());

        getDataHandler().addData(dataList);
    }

    protected abstract Optional<CompromisedAssembly> attackComponent(AssemblyContext component, CredentialChange change,
            EObject source);

    private Collection<CompromisedAssembly> filterExsiting(Collection<CompromisedAssembly> components,
            CredentialChange change) {
        return components.stream().filter(component -> !contains(component, change)).collect(Collectors.toList());

    }

    private boolean contains(CompromisedAssembly component, CredentialChange change) {
        return change.getCompromisedassembly().stream().anyMatch(referenceComponent -> EcoreUtil
                .equals(referenceComponent.getAffectedElement(), component.getAffectedElement()));
    }

}
