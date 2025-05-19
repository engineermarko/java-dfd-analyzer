package com.threatmodel.analyzer.model;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents a data flow between components in the system
 */
public class DataFlow {
    private String id;
    private String sourceId;
    private String destinationId;
    private String dataStructureId;
    private String description;
    private String protocol;
    private boolean isExternal;
    private DataFlowType type;
    private Map<String, Object> metadata = new HashMap<>();
    
    public enum DataFlowType {
        INPUT,
        OUTPUT,
        INTERNAL,
        DATABASE_READ,
        DATABASE_WRITE,
        API_CALL,
        FILE_IO,
        OTHER
    }
    
    public DataFlow(String id, String sourceId, String destinationId, String dataStructureId) {
        this.id = id;
        this.sourceId = sourceId;
        this.destinationId = destinationId;
        this.dataStructureId = dataStructureId;
        this.type = DataFlowType.OTHER;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSourceId() {
        return sourceId;
    }

    public void setSourceId(String sourceId) {
        this.sourceId = sourceId;
    }

    public String getDestinationId() {
        return destinationId;
    }

    public void setDestinationId(String destinationId) {
        this.destinationId = destinationId;
    }

    public String getDataStructureId() {
        return dataStructureId;
    }

    public void setDataStructureId(String dataStructureId) {
        this.dataStructureId = dataStructureId;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public boolean isExternal() {
        return isExternal;
    }

    public void setExternal(boolean isExternal) {
        this.isExternal = isExternal;
    }

    public DataFlowType getType() {
        return type;
    }

    public void setType(DataFlowType type) {
        this.type = type;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void addMetadata(String key, Object value) {
        this.metadata.put(key, value);
    }
}
