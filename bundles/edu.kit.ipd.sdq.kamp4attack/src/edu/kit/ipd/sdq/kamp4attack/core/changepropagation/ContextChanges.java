package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import java.lang.annotation.Target;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.compare.EMFCompare;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.model.ContextAttribute;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.SystemPolicySpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class ContextChanges extends Change<ContextAttribute> {

    public ContextChanges(BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<ContextAttribute> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(modelStorage, ContextAttribute.class);
    }

    public void calculateContextToAssemblyPropagation(CredentialChange changes) {
        var contexts = changes.getContextchange().stream().map(ContextChange::getAffectedElement)
                .collect(Collectors.toList());

        var assembly = changes.getCompromisedassembly().stream().map(CompromisedAssembly::getAffectedElement)
                .collect(Collectors.toList());

    }

    private List<AssemblyContext> propagateFromAssemblyContext(List<ContextAttribute> contexts,
            AssemblyContext component) {
        var system = this.modelStorage.getAssembly();
        var targetConnectors = system.getConnectors__ComposedStructure().stream()
                .filter(AssemblyConnector.class::isInstance).map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiredRole_AssemblyConnector(), component))
                .collect(Collectors.toList());

        var targetComponents = targetConnectors.stream()
                .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector).collect(Collectors.toList());

        return null;

    }

    private void getContextList(AssemblyContext context) {
        var targetSpecification = modelStorage.getSpecification().getPolicyspecification().stream()
                .filter(SystemPolicySpecification.class::isInstance).map(SystemPolicySpecification.class::cast)
                .filter(e -> EcoreUtil.equals(e.getAssemblycontext(), context)).collect(Collectors.toList());
        
        //TODO filter for context set
    }

}
