package edu.kit.ipd.sdq.kamp4attack.core;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.core.entity.Entity;

public class CachePDP {

    private final Map<String, PDPResult> cache = new HashMap<>();

    private static CachePDP instance;

    private CachePDP() {
        // TODO Auto-generated constructor stub
    }

    public static CachePDP instance() {
        return instance == null ? instance = new CachePDP() : instance;
    }

    public void insert(final Entity target, final PDPResult result) {
        this.cache.put(target.getId(), result);

    }

    public void insert(final Entity target, final Entity method, final PDPResult result) {
        this.cache.put(target.getId() + method.getId(), result);
    }

    public Optional<PDPResult> get(final Entity target) {

        return Optional.ofNullable(this.cache.get(target.getId()));
    }

    public Optional<PDPResult> get(final Entity target, final Entity method) {

        return Optional.ofNullable(this.cache.get(target.getId() + method.getId()));
    }

    public void clearCache() {
        this.cache.clear();
    }
}
