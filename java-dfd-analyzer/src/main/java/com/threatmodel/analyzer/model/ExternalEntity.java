package com.threatmodel.analyzer.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents an external entity that interacts with the system
 */
public class ExternalEntity {
    private String name;
    private String description;
    private List<String> protocols = new ArrayList<>();
    private Map<String, Object> metadata = new HashMap<>();
    private ExternalEntityType type;
    
    public enum ExternalEntityType {
        USER,
        SYSTEM,
        SERVICE,
        DATABASE,
        OTHER
    }
    
    public ExternalEntity(String name) {
        this.name = name;
        this.type = ExternalEntityType.OTHER;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getProtocols() {
        return protocols;
    }

    public void addProtocol(String protocol) {
        if (!protocols.contains(protocol)) {
            this.protocols.add(protocol);
        }
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void addMetadata(String key, Object value) {
        this.metadata.put(key, value);
    }

    public ExternalEntityType getType() {
        return type;
    }

    public void setType(ExternalEntityType type) {
        this.type = type;
    }
}
