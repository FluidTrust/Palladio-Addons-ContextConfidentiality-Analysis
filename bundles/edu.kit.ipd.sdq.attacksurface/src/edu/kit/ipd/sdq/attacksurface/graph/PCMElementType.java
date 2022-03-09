package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.Objects;
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

/**
 * Represents the type of a {@link PCMElement}
 * 
 * @author ugnwq
 * @version 1.0
 */
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
    
    /**
     * 
     * @param entity - the entity
     * @return type of the entity or {@code null} if no type fits
     */
    public static PCMElementType typeOf(final Entity entity) {
        for (final var type : values()) {
            if (type.clazz.isInstance(entity)) {
                return type;
            }
        }
        return null;
    }
    
    /**
     * 
     * @param pcmElement - the {@link PCMElement}
     * @return the type of the element or {@code null} if no type fits
     */
    public static PCMElementType typeOf(final PCMElement pcmElement) {
        for (final var type : values()) {
            if (type.clazz.isInstance(type.getEntity(pcmElement))) {
                return type;
            }
        }
        return null;
    }
    
    /**
     * 
     * @param original - the original element
     * @return copy of the element
     */
    public static PCMElement copy(final PCMElement original) {
        final var type = PCMElementType.typeOf(original);
        return type != null ? type.toPCMElement(type.getEntity(original)) : null;
    }
    
    /**
     * 
     * @param entity - the entity
     * @return the entity inside an {@link PCMElement}
     */
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
    
    /**
     * 
     * @param pcmElement - the element
     * @return the entity inside the element
     */
    public Entity getEntity(final PCMElement pcmElement) {
        if (pcmElement == null) {
            return null;
        }
        
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
    
    /**
     * 
     * @param entity
     * @return a predicate over a system integration and an entity returning {@code true} on ID equality of the
     * entity and the entity contained in the PCMElement of the system integration
     */
    public Predicate<SystemIntegration> getElementIdEqualityPredicate(final Entity entity) {
        return s -> {
            final var pcmElement = s.getPcmelement();
            final var entityOfPcmElement = getEntity(pcmElement);
            if (entityOfPcmElement != null) {
                return Objects.equals(entityOfPcmElement.getId(), entity.getId());
            }
            return false;
        };
    }
}
