package com.threatmodel.analyzer.utils;

import java.util.HashMap;
import java.util.Map;

import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;

/**
 * Utility class for extracting annotations from Java elements
 */
public class AnnotationExtractor {
    
    /**
     * Extracts annotations from a Java element
     * 
     * @param declaration The element to extract annotations from
     * @return A map of annotation names to values
     */
    public static Map<String, String> extractAnnotations(BodyDeclaration<?> declaration) {
        Map<String, String> annotations = new HashMap<>();
        
        for (AnnotationExpr annotation : declaration.getAnnotations()) {
            String name = annotation.getNameAsString();
            String value = null;
            
            if (annotation.isSingleMemberAnnotationExpr()) {
                SingleMemberAnnotationExpr singleExpr = annotation.asSingleMemberAnnotationExpr();
                value = singleExpr.getMemberValue().toString();
            } else if (annotation.isNormalAnnotationExpr()) {
                NormalAnnotationExpr normalExpr = annotation.asNormalAnnotationExpr();
                NodeList<MemberValuePair> pairs = normalExpr.getPairs();
                
                // If there are multiple pairs, join them
                if (!pairs.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (MemberValuePair pair : pairs) {
                        if (sb.length() > 0) {
                            sb.append(", ");
                        }
                        sb.append(pair.getNameAsString()).append("=").append(pair.getValue());
                    }
                    value = sb.toString();
                }
            } else {
                // Marker annotation
                value = "true";
            }
            
            annotations.put(name, value);
        }
        
        return annotations;
    }
}
