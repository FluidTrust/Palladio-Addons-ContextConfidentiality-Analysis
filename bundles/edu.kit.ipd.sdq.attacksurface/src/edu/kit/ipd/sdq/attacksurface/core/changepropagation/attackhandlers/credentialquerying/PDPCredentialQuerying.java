package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.credentialquerying;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import org.palladiosimulator.pcm.confidentiality.context.helper.PolicyHelper;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.Evaluate;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.Signature;

import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

public class PDPCredentialQuerying implements CredentialQuerying {
    private final BlackboardWrapper modelStorage;
    
    public PDPCredentialQuerying(final BlackboardWrapper modelStorage) {
        this.modelStorage = modelStorage;
    }

    /**
     * Sends an access request to the policy decision point (PDP). <br \> <b>Important:</b> before
     * the request the PDP must be initialised. This can be done with
     * {@link Evaluate#initialize(String)}
     *
     * @param target
     *            requested system entity
     * @param credentials
     *            current credentials
     * @return the result
     *
     * @see Evaluate#initialize(String)
     */
    @Override
    public Optional<PDPResult> queryAccessForEntity(Entity target, List<? extends UsageSpecification> credentials,
            Signature signature) {
        final var listComponent = new LinkedList<>(Arrays.asList(target));
        final var listSubject = new ArrayList<UsageSpecification>();
        final var listEnvironment = new ArrayList<UsageSpecification>();
        final var listResource = new ArrayList<UsageSpecification>();
        final var listXML = new ArrayList<UsageSpecification>();
        final var listOperation = new ArrayList<UsageSpecification>();

        if (signature == null) {
            PolicyHelper.createRequestAttributes(listComponent, credentials, listSubject, listEnvironment, listResource,
                    listXML);
        } else {
            PolicyHelper.createRequestAttributes(signature, listComponent, credentials, listSubject, listEnvironment,
                    listResource, listOperation, listXML);
        }

        final var result = getModelStorage().getEval().evaluate(listSubject, listEnvironment, listResource,
                listOperation, listXML);
        return result;
    }

    @Override
    public BlackboardWrapper getModelStorage() {
        return this.modelStorage;
    }

}
