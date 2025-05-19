package com.threatmodel.analyzer.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.threatmodel.analyzer.model.DataFlow;
import com.threatmodel.analyzer.model.DataFlow.DataFlowType;
import com.threatmodel.analyzer.model.DataStore;
import com.threatmodel.analyzer.model.DataStructure;
import com.threatmodel.analyzer.model.ExternalEntity;
import com.threatmodel.analyzer.model.Process;

/**
 * Utility class for detecting data flows between system components
 */
public class DataFlowDetector {
    
    private final Map<String, DataStructure> dataStructures;
    private final Map<String, Process> processes;
    private final Map<String, ExternalEntity> externalEntities;
    private final Map<String, DataStore> dataStores;
    
    public DataFlowDetector(
            Map<String, DataStructure> dataStructures,
            Map<String, Process> processes,
            Map<String, ExternalEntity> externalEntities,
            Map<String, DataStore> dataStores) {
        this.dataStructures = dataStructures;
        this.processes = processes;
        this.externalEntities = externalEntities;
        this.dataStores = dataStores;
    }
    
    /**
     * Detects data flows between components
     * 
     * @return A list of detected data flows
     */
    public List<DataFlow> detectDataFlows() {
        List<DataFlow> flows = new ArrayList<>();
        
        // Detect flows from processes to processes
        detectProcessToProcessFlows(flows);
        
        // Detect flows from external entities to processes
        detectExternalToProcessFlows(flows);
        
        // Detect flows from processes to external entities
        detectProcessToExternalFlows(flows);
        
        // Detect flows from processes to data stores
        detectProcessToDataStoreFlows(flows);
        
        // Detect flows from data stores to processes
        detectDataStoreToProcessFlows(flows);
        
        return flows;
    }
    
    /**
     * Detects data flows between processes
     */
    private void detectProcessToProcessFlows(List<DataFlow> flows) {
        for (Process sourceProcess : processes.values()) {
            // Check output data structures of this process
            for (String outputDataStructureId : sourceProcess.getOutputDataStructureIds()) {
                // Find processes that take this data structure as input
                for (Process destProcess : processes.values()) {
                    if (!sourceProcess.getId().equals(destProcess.getId()) && 
                            destProcess.getInputDataStructureIds().contains(outputDataStructureId)) {
                        // Create a data flow between these processes
                        DataFlow flow = new DataFlow(
                                "flow-" + UUID.randomUUID().toString(),
                                sourceProcess.getId(),
                                destProcess.getId(),
                                outputDataStructureId);
                        
                        flow.setType(DataFlowType.INTERNAL);
                        flow.setDescription(sourceProcess.getName() + " -> " + destProcess.getName());
                        
                        flows.add(flow);
                    }
                }
            }
        }
    }
    
    /**
     * Detects data flows from external entities to processes
     */
    private void detectExternalToProcessFlows(List<DataFlow> flows) {
        for (ExternalEntity entity : externalEntities.values()) {
            // For REST endpoints, create flows to the matching process
            if (entity.getType() == ExternalEntity.ExternalEntityType.USER && 
                    entity.getName().startsWith("WebClient-")) {
                
                // Extract controller name from entity name
                String controllerName = entity.getName().substring("WebClient-".length());
                
                // Find processes that correspond to methods in this controller
                for (Process process : processes.values()) {
                    if (process.getId().contains(controllerName)) {
                        // For each input data structure, create a flow
                        for (String inputDataStructureId : process.getInputDataStructureIds()) {
                            DataFlow flow = new DataFlow(
                                    "flow-" + UUID.randomUUID().toString(),
                                    entity.getName(),
                                    process.getId(),
                                    inputDataStructureId);
                            
                            flow.setType(DataFlowType.INPUT);
                            flow.setDescription("Web request from " + entity.getName() + " to " + process.getName());
                            flow.setExternal(true);
                            flow.setProtocol("HTTP/HTTPS");
                            
                            flows.add(flow);
                        }
                    }
                }
            }
            
            // For service clients, create flows to related processes
            if (entity.getType() == ExternalEntity.ExternalEntityType.SERVICE && 
                    entity.getName().startsWith("Service-")) {
                
                // Extract service name from entity name
                String serviceName = entity.getName().substring("Service-".length());
                
                // Find processes that might call this service
                for (Process process : processes.values()) {
                    if (process.getId().contains(serviceName) || 
                            process.getDescription() != null && process.getDescription().contains(serviceName)) {
                        
                        // Create a flow for each input to the process
                        for (String inputDataStructureId : process.getInputDataStructureIds()) {
                            DataFlow flow = new DataFlow(
                                    "flow-" + UUID.randomUUID().toString(),
                                    entity.getName(),
                                    process.getId(),
                                    inputDataStructureId);
                            
                            flow.setType(DataFlowType.API_CALL);
                            flow.setDescription("Service call response from " + entity.getName() + " to " + process.getName());
                            flow.setExternal(true);
                            
                            // Get the protocol from the entity
                            if (!entity.getProtocols().isEmpty()) {
                                flow.setProtocol(entity.getProtocols().get(0));
                            }
                            
                            flows.add(flow);
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Detects data flows from processes to external entities
     */
    private void detectProcessToExternalFlows(List<DataFlow> flows) {
        for (ExternalEntity entity : externalEntities.values()) {
            // For REST endpoints, create flows from the matching process
            if (entity.getType() == ExternalEntity.ExternalEntityType.USER && 
                    entity.getName().startsWith("WebClient-")) {
                
                // Extract controller name from entity name
                String controllerName = entity.getName().substring("WebClient-".length());
                
                // Find processes that correspond to methods in this controller
                for (Process process : processes.values()) {
                    if (process.getId().contains(controllerName)) {
                        // For each output data structure, create a flow
                        for (String outputDataStructureId : process.getOutputDataStructureIds()) {
                            DataFlow flow = new DataFlow(
                                    "flow-" + UUID.randomUUID().toString(),
                                    process.getId(),
                                    entity.getName(),
                                    outputDataStructureId);
                            
                            flow.setType(DataFlowType.OUTPUT);
                            flow.setDescription("Web response from " + process.getName() + " to " + entity.getName());
                            flow.setExternal(true);
                            flow.setProtocol("HTTP/HTTPS");
                            
                            flows.add(flow);
                        }
                    }
                }
            }
            
            // For service clients, create flows from related processes
            if (entity.getType() == ExternalEntity.ExternalEntityType.SERVICE && 
                    entity.getName().startsWith("Service-")) {
                
                // Extract service name from entity name
                String serviceName = entity.getName().substring("Service-".length());
                
                // Find processes that might call this service
                for (Process process : processes.values()) {
                    if (process.getId().contains(serviceName) || 
                            process.getDescription() != null && process.getDescription().contains(serviceName)) {
                        
                        // Create a flow for each output from the process
                        for (String outputDataStructureId : process.getOutputDataStructureIds()) {
                            DataFlow flow = new DataFlow(
                                    "flow-" + UUID.randomUUID().toString(),
                                    process.getId(),
                                    entity.getName(),
                                    outputDataStructureId);
                            
                            flow.setType(DataFlowType.API_CALL);
                            flow.setDescription("Service call request from " + process.getName() + " to " + entity.getName());
                            flow.setExternal(true);
                            
                            // Get the protocol from the entity
                            if (!entity.getProtocols().isEmpty()) {
                                flow.setProtocol(entity.getProtocols().get(0));
                            }
                            
                            flows.add(flow);
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Detects data flows from processes to data stores
     */
    private void detectProcessToDataStoreFlows(List<DataFlow> flows) {
        for (DataStore dataStore : dataStores.values()) {
            // Extract store name 
            String storeName = dataStore.getName();
            
            // Find processes that might write to this data store
            for (Process process : processes.values()) {
                boolean mayWrite = process.getId().contains("save") || 
                                   process.getId().contains("update") || 
                                   process.getId().contains("create") || 
                                   process.getId().contains("delete") || 
                                   process.getId().contains("insert") || 
                                   process.getId().contains("persist");
                
                if (mayWrite && (process.getId().contains(storeName) || 
                        (process.getDescription() != null && process.getDescription().contains(storeName)))) {
                    
                    // Create a flow for each output from the process
                    for (String outputDataStructureId : process.getOutputDataStructureIds()) {
                        DataFlow flow = new DataFlow(
                                "flow-" + UUID.randomUUID().toString(),
                                process.getId(),
                                dataStore.getId(),
                                outputDataStructureId);
                        
                        flow.setType(DataFlowType.DATABASE_WRITE);
                        flow.setDescription("Data write from " + process.getName() + " to " + dataStore.getName());
                        
                        // Update the data store's data structures
                        dataStore.addDataStructureId(outputDataStructureId);
                        
                        flows.add(flow);
                    }
                }
            }
        }
    }
    
    /**
     * Detects data flows from data stores to processes
     */
    private void detectDataStoreToProcessFlows(List<DataFlow> flows) {
        for (DataStore dataStore : dataStores.values()) {
            // Extract store name 
            String storeName = dataStore.getName();
            
            // Find processes that might read from this data store
            for (Process process : processes.values()) {
                boolean mayRead = process.getId().contains("get") || 
                                  process.getId().contains("find") || 
                                  process.getId().contains("read") || 
                                  process.getId().contains("load") || 
                                  process.getId().contains("retrieve") || 
                                  process.getId().contains("search");
                
                if (mayRead && (process.getId().contains(storeName) || 
                        (process.getDescription() != null && process.getDescription().contains(storeName)))) {
                    
                    // Create a flow for each data structure stored in the data store
                    for (String dataStructureId : dataStore.getDataStructureIds()) {
                        DataFlow flow = new DataFlow(
                                "flow-" + UUID.randomUUID().toString(),
                                dataStore.getId(),
                                process.getId(),
                                dataStructureId);
                        
                        flow.setType(DataFlowType.DATABASE_READ);
                        flow.setDescription("Data read from " + dataStore.getName() + " to " + process.getName());
                        
                        flows.add(flow);
                    }
                }
            }
        }
    }
}
