package edu.kit.ipd.sdq.attacksurface.attackdag;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.MethodSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.CompositeComponent;
import org.palladiosimulator.pcm.repository.RepositoryComponent;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

public enum PCMElementType {
    RESOURCE_CONTAINER(ResourceContainer.class),
    
    LINKING_RESOURCE(LinkingResource.class),
    
    COMPOSITE_COMPONENT(CompositeComponent.class),
    
    BASIC_COMPONENT(RepositoryComponent.class),
    
    ASSEMBLY_CONTEXT(AssemblyContext.class),
    
    METHOD_SPECIFICATION(MethodSpecification.class)
    ;
    
    private final Class<? extends Entity> clazz;
    
    private PCMElementType(Class<? extends Entity> clazz) {
        this.clazz = clazz;
    }
    
    public static PCMElementType typeOf(final Entity entity) {
        for (final var type : values()) {
            if (type.clazz.isInstance(entity)) {
                return type;
            }
        }
        return null;
    }
    
    public static PCMElementType typeOf(final PCMElement pcmElement) {
        for (final var type : values()) {
            if (type.clazz.isInstance(type.getEntity(pcmElement))) {
                return type;
            }
        }
        return null;
    }
    
    public PCMElement toPCMElement(final Entity entity) {
        Objects.requireNonNull(entity);
        if (!this.clazz.isInstance(entity)) {
            throw new IllegalArgumentException("invalid type, should be \"" + 
                    this.clazz.getName() + "\" but is \"" + entity.getClass().getName() + "\"");            
        }
        
        final var pcmElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        switch(this) {
            case RESOURCE_CONTAINER:
                pcmElement.setResourcecontainer((ResourceContainer) entity);
                break;
            case LINKING_RESOURCE:
                pcmElement.setLinkingresource((LinkingResource) entity);
                break;
            case BASIC_COMPONENT:
                pcmElement.setBasiccomponent((RepositoryComponent) entity);
                break;
            case COMPOSITE_COMPONENT:
                pcmElement.setCompositecomponent((CompositeComponent) entity);
                break;
            case ASSEMBLY_CONTEXT:
                pcmElement.setAssemblycontext((AssemblyContext) entity);
                break;
            case METHOD_SPECIFICATION:
                pcmElement.setMethodspecification((MethodSpecification) entity);
                break;
            default:
                assert false;
                break;
        }
        
        return pcmElement;
    }
    
    public Entity getEntity(final PCMElement pcmElement) {
        Entity ret = null;
        switch(this) {
            case RESOURCE_CONTAINER:
                ret = pcmElement.getResourcecontainer();
                break;
            case LINKING_RESOURCE:
                ret = pcmElement.getLinkingresource();
                break;
            case BASIC_COMPONENT:
                ret = pcmElement.getBasiccomponent();
                break;
            case COMPOSITE_COMPONENT:
                ret = pcmElement.getCompositecomponent();
                break;
            case ASSEMBLY_CONTEXT:
                ret = pcmElement.getAssemblycontext();
                break;
            case METHOD_SPECIFICATION:
                ret = pcmElement.getMethodspecification();
                break;
            default:
                assert false;
                break;
        }
        return ret;
    }
    
    public Predicate<SystemIntegration> getElementIdEqualityPredicate(final Entity entity) {
        return s -> {
            final var pcmElement = s.getPcmelement();
            if (pcmElement != null) {
                final var entityOfPcmElement = getEntity(pcmElement);
                return entityOfPcmElement.getId().equals(entity.getId());
            }
            return false;
        };
    }
}
