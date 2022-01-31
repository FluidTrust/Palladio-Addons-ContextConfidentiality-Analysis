package edu.kit.ipd.sdq.attacksurface.core;

import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.eclipse.emf.common.notify.Adapter;
import org.eclipse.emf.common.notify.Notification;
import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.common.util.TreeIterator;
import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EClassifier;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.EOperation;
import org.eclipse.emf.ecore.EPackage;
import org.eclipse.emf.ecore.EReference;
import org.eclipse.emf.ecore.EStructuralFeature;
import org.eclipse.emf.ecore.resource.Resource;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.RoleSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.BasicComponent;

import edu.kit.ipd.sdq.attacksurface.attackdag.AttackDAG;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.LinkingPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.LinkingPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationVulnerability;
import edu.kit.ipd.sdq.kamp.propagation.AbstractChangePropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.core.CacheVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedAssemblyImpl;

/**
 * Entry point for attack surface propagation
 *
 * @author majuwa
 * @author ugnwq
 */

@Component
public class AttackSurfaceAnalysis implements AbstractChangePropagationAnalysis<BlackboardWrapper> {

    private CredentialChange changePropagationDueToCredential;
    
    //TODO more general: "element", i.e. NamedEntity, ModifyEntity ?
    private AssemblyContext criticalAssembly; 
    
    private AttackDAG attackDAG;

    @Override
    public void runChangePropagationAnalysis(final BlackboardWrapper board) {

        // Setup
        this.changePropagationDueToCredential = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        CachePDP.instance().clearCache();
        CacheCompromised.instance().reset();
        CacheVulnerability.instance().reset();
        CacheCompromised.instance().register(this.changePropagationDueToCredential);
        
        // prepare
        createInitialStructure(board);
        this.attackDAG = new AttackDAG(this.criticalAssembly);
        
        //TODO adapt
        // Calculate
        do {
            this.changePropagationDueToCredential.setChanged(false);
            
            calculateAndMarkAssemblyPropagation(board);
            calculateAndMarkResourcePropagation(board);
            /*TODO calculateAndMarkLinkingPropagation(board);*/
        } while (this.changePropagationDueToCredential.isChanged()); 

        // Clear caches
        CachePDP.instance().clearCache();
        CacheCompromised.instance().reset();
        CacheVulnerability.instance().reset();
    }

    private void createInitialStructure(BlackboardWrapper board) {
    	//TODO adapt!
    	
    	final var repository = board.getModificationMarkRepository();
        final var seedModification = repository.getSeedModifications();
        final var attackers = seedModification.getSurfaceattackcomponent();
        if (attackers == null) {
            throw new IllegalStateException("No seed modification found");
        }

        repository.getChangePropagationSteps().clear();

        for (final var attacker : attackers) { //TODO at the moment only one attacker allowed
            final var localAttacker = attacker.getAffectedElement();
            this.criticalAssembly = localAttacker.getCriticalElement().getAssemblycontext(); //TODO more general

            final var listCredentialChanges = localAttacker.getAttacker().getCredentials()
                    .stream()
                    .map(context -> {
                final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
                change.setAffectedElement(context);
                return change;
            }).collect(Collectors.toList());

            this.changePropagationDueToCredential.getContextchange().addAll(listCredentialChanges);

            // convert affectedResources to changes
            final var affectedRessourcesList = localAttacker.getAttacker().
                    getCompromisedResources().stream().map(resource -> {
                final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                change.setAffectedElement(resource);
                return change;
            }).collect(Collectors.toList());
            this.changePropagationDueToCredential.getCompromisedresource().addAll(affectedRessourcesList);

            // convert affectedAssemblyContexts to changes
            /*var assemblyHandler = new AssemblyContextHandler(board, new DataHandlerAttacker(this.changePropagationDueToCredential)) {
                @Override
                protected Optional<CompromisedAssembly> attackComponent(AssemblyContext component, CredentialChange change,
                        EObject source){
                    final var compromisedComponent = KAMP4attackModificationmarksFactory.eINSTANCE
                            .createCompromisedAssembly();
                    compromisedComponent.setAffectedElement(component);
                    return Optional.of(compromisedComponent);
                }
            };

            assemblyHandler.attackAssemblyContext(Arrays.asList(this.criticalAssembly), this.changePropagationDueToCredential, null);
            */ //TODO remove ^ 
            
            //TODO add all possible attacks to the attack container and the attacker (??)
            
            // convert affectedLinkingResources to changes
            final var affectedLinkingList = localAttacker.getAttacker().getCompromisedLinkingResources().stream()
                    .map(linkingResource -> {
                        final var change = KAMP4attackModificationmarksFactory.eINSTANCE
                                .createCompromisedLinkingResource();
                        change.setAffectedElement(linkingResource);
                        return change;
                    }).collect(Collectors.toList());
            this.changePropagationDueToCredential.getCompromisedlinkingresource().addAll(affectedLinkingList);

        }
        board.getModificationMarkRepository().getChangePropagationSteps().add(this.changePropagationDueToCredential);
		
	}
	
    /**
     * Calculates the propagation starting from {@link AssemblyContext}s. 
     * The analyses start from the critical element and try to calculate back possible attack paths to it. <br/>
     * TODO: consider credentials and propagation to other model elements except assembly contexts 
     * 
     * @param board - the model storage
     */
    private void calculateAndMarkAssemblyPropagation(final BlackboardWrapper board) {
        this.changePropagationDueToCredential.setChanged(false);
		
        //TODO complete implementation
        
		final var list = new ArrayList<AssemblyContextPropagation>();
        list.add(new AssemblyContextPropagationVulnerability(board, this.changePropagationDueToCredential, this.attackDAG));
        //list.add(new AssemblyContextPropagationContext(board));
        for (final var analysis : list) { //TODO adapt
            analysis.calculateAssemblyContextToAssemblyContextPropagation(); 
            //TODO add others
        }
    }
    

    private void calculateAndMarkResourcePropagation(BlackboardWrapper board) {
        // TODO implement
        
    }

}
