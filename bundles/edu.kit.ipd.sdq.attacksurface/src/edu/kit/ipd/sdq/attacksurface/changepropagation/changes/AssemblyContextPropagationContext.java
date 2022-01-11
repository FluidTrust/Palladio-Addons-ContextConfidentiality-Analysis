package edu.kit.ipd.sdq.attacksurface.changepropagation.changes;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.attacksurface.attackdag.AttackDAG;
import edu.kit.ipd.sdq.attacksurface.attackdag.AttackStatusDescriptorNodeContent;
import edu.kit.ipd.sdq.attacksurface.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.MethodContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class AssemblyContextPropagationContext extends AssemblyContextChange {
    private final AttackDAG attackDAG;
    
    public AssemblyContextPropagationContext(final BlackboardWrapper v, final CredentialChange changes, final AttackDAG attackDAG) {
        super(v, changes);
        this.attackDAG = attackDAG;
    }

    @Override
    protected ResourceContainerHandler getLocalResourceHandler() {
    	return null; //TODO
        //TODO return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(getAttacker()));
    }

    @Override
    protected AssemblyContextHandler getAssemblyHandler() {
        return new AssemblyContextContext(this.modelStorage, new DataHandlerAttacker(changes));
    }

    @Override
    protected LinkingResourceHandler getLinkingHandler() {
    	return null; //TODO
        //TODO return new LinkingResourceContext(this.modelStorage, new DataHandlerAttacker(getAttacker()));
    }

    @Override
    protected ResourceContainerHandler getRemoteResourceHandler() {
    	return null; //TODO
        //TODO return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(getAttacker()));
    }

    @Override
    protected void handleSeff(final CredentialChange changes, final List<ServiceRestriction> services,
            final AssemblyContext source) {
        final var handler = new MethodContext(this.modelStorage, new DataHandlerAttacker(changes));
        handler.attackService(services, changes, source);
        
        //TODO maybe add this somewhere else or write new
        final boolean isSourceCompromised = 
                changes.getCompromisedassembly()
                    .stream()
                    .map(c -> c.getAffectedElement())
                    .anyMatch(a -> a.getId().equals(source.getId()));
        //TODO evtl. anders aufbauen generell ^: die analyse muss ein anderes interface verwenden und die elemente durchgehen
        if (isSourceCompromised) {
            final AttackStatusDescriptorNodeContent nodeContent = new AttackStatusDescriptorNodeContent(source);
            final AttackStatusDescriptorNodeContent foundNodeContent;
            if (this.attackDAG.contains(nodeContent)) {
                foundNodeContent = this.attackDAG.find(nodeContent).getContent();
            } else {
                foundNodeContent = nodeContent;
                this.attackDAG.addToContextParentNode(foundNodeContent);
            }
            foundNodeContent.setCompromised(true);
            adaptDAG(changes, foundNodeContent);
            //TODO loop
        }
    }

    private void adaptDAG(final CredentialChange changes, 
            final AttackStatusDescriptorNodeContent compromisedNodeContent) {
        // TODO implement: decide wether to attack elements closer or more far away from root (critical)
        
    }

}
