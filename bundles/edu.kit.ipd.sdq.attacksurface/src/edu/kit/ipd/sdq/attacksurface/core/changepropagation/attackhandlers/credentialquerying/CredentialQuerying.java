package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.credentialquerying;

import java.util.List;
import java.util.Optional;

import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.Signature;

import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

/**
 * Represents an interface for querying access for an entity using credentials.
 * 
 * @author ugnwq
 * @version 1.0
 */
public interface CredentialQuerying {
    
    /**
     * Calls the {@link #queryAccessForEntity(Entity, List, Signature)} with no signature.
     * 
     * @param target - the target entity
     * @param credentials - the credentials
     * @return the result
     */
    default Optional<PDPResult> queryAccessForEntity(final Entity target,
            final List<? extends UsageSpecification> credentials) {
        return queryAccessForEntity(target, credentials, null);
    }
    
    /**
     * Querys the access for the given entity and the given credentials.
     * 
     * @param target - the given entity
     * @param credentials - the credentials
     * @param signature - the signature, may be {@code null}
     * @return the result of the querying
     */
    Optional<PDPResult> queryAccessForEntity(final Entity target,
            final List<? extends UsageSpecification> credentials, final Signature signature);
    
    /**
     * 
     * @return the model storage
     */
    BlackboardWrapper getModelStorage();
}
