package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.CVSurface;
import edu.kit.ipd.sdq.attacksurface.graph.VulnerabilitySurface;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AssemblyContextHandler extends AttackHandler  {

    protected AssemblyContextHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler,
            final AttackGraph attackGraph) {
        super(modelStorage, dataHandler, attackGraph);
    }

    public void attackAssemblyContext(final Collection<AssemblyContext> components, final CredentialChange change,
            final Entity source) {
        final var compromisedComponent = components.stream().map(e -> attackComponent(e, change, source))
                .flatMap(Optional::stream).collect(Collectors.toList()); 
        //TODO also consider how attack was done in compromisation (whilch vuln. and credentials were used)
        //TODO so that a different kind of attack generates a new attack path
        final var newCompromisedComponent = filterExsitingComponent(compromisedComponent);
        if (!newCompromisedComponent.isEmpty()) {
            handleDataExtraction(newCompromisedComponent);
            change.setChanged(true);
            final var selectedNodeBefore = getAttackGraph().getSelectedNode();
            final var attackSource = new AttackStatusNodeContent(source);
            for (final var newlyCompromised : newCompromisedComponent) {
                final var compromisedNode = new AttackStatusNodeContent(newlyCompromised.getAffectedElement());
                final var causingElements = newlyCompromised.getCausingElements();
                compromise(causingElements, compromisedNode, attackSource);
            }
            getAttackGraph().setSelectedNode(selectedNodeBefore);
            
            /*TODO maybe remove CollectionHelper.addService(newCompromisedComponent, getModelStorage().getVulnerabilitySpecification(),
                    change);*/
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

    protected abstract Optional<CompromisedAssembly> attackComponent(AssemblyContext component, CredentialChange change,
            EObject source);

    private Collection<CompromisedAssembly> filterExsitingComponent(final Collection<CompromisedAssembly> components) {
        return components.stream().filter(component -> !containsComponent(component))
                .collect(Collectors.toList());
    }

    private boolean containsComponent(final CompromisedAssembly component) {
        return getAttackGraph().getCompromisedNodes().stream()
                .map(AttackStatusNodeContent::getContainedElement)
                .anyMatch(referenceEntity -> EcoreUtil
                .equals(referenceEntity, component.getAffectedElement()));
    }

}
