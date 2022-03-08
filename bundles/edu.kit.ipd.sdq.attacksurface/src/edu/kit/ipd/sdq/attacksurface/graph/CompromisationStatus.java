package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.stream.Collectors;

public enum CompromisationStatus {
    /**
     * if the node was not compromised
     */
    NOT_COMPROMISED(0), 
    
    /**
     * if the node was attacked and credentials were extracted
     */
    ATTACKED_AND_CREDENTIALS_EXTRACTED(1),
    
    /**
     * if the node was completely compromised (takeover)
     */
    COMPROMISED(2);
    
    private final int severity;
    
    private CompromisationStatus(final int severity) {
        this.severity = severity;
    }
    
    public int getSeverity() {
        return this.severity;
    }

    public static Comparator<CompromisationStatus> getSeverityComparator() {
        return (a, b) -> Integer.valueOf(a.severity).compareTo(b.severity);
    }

    public CompromisationStatus increase() {
        return of(this.severity + 1);
    }

    private CompromisationStatus of(final int maxSeverity) {
        final var vals = Arrays
                .stream(values())
                .sorted(getSeverityComparator())
                .collect(Collectors.toList());
        Collections.reverse(vals);
        for(final var val : vals) {
            if (val.severity <= maxSeverity) {
                return val;
            }
        }
        return null;
    }
}
