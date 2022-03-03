package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.CauseGetter;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdgeContent;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.CVSurface;
import edu.kit.ipd.sdq.attacksurface.graph.VulnerabilitySurface;
import edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractModification;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;

public abstract class AssemblyContextHandler extends AttackHandler  {

    protected AssemblyContextHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler,
            final AttackGraph attackGraph) {
        super(modelStorage, dataHandler, attackGraph);
    }

    public void attackAssemblyContext(final List<AssemblyContext> components, final CredentialChange change,
            final Entity source, final boolean doesAttackComeFromContainingContainer) {
        final var compromisedComponents = components
                .stream()
                .map(e -> doesAttackComeFromContainingContainer 
                        ? Optional.of(HelperCreationCompromisedElements.createCompromisedAssembly(e, List.of(source)))
                                : attackComponent(e, change, source)
                    )
                .flatMap(Optional::stream).collect(Collectors.toList()); 
        
        final var newCompromisedComponents = filterExistingEdges(compromisedComponents, source);
        if (!newCompromisedComponents.isEmpty()) {
            handleDataExtraction(newCompromisedComponents);
            change.setChanged(true);
            final var selectedNodeBefore = getAttackGraph().getSelectedNode();
            final var attackSource = new AttackStatusNodeContent(source);
            for (final var newlyCompromised : newCompromisedComponents) {
                final var compromisedNode = new AttackStatusNodeContent(newlyCompromised.getAffectedElement());
                final var causingElements = newlyCompromised.getCausingElements();
                compromise(causingElements, compromisedNode, attackSource);
            }
            getAttackGraph().setSelectedNode(selectedNodeBefore);
            
            /*TODO maybe remove CollectionHelper.addService(newCompromisedComponent, getModelStorage().getVulnerabilitySpecification(),
                    change);*/
        }
    }
    
    protected Collection<CompromisedAssembly> filterExistingEdges(
            final List<CompromisedAssembly> compromisedComponents, final Entity source) {
        final var clazz = CompromisedAssembly.class;
        return filterExistingEdges(compromisedComponents, source, clazz)
                .stream()
                .map(clazz::cast)
                .collect(Collectors.toList());
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

}
