package com.synjones.tsm.test.until;
import java.util.*;
public class SequenceUtils {
  private static List generalFormSequence(Map params, List ignoreFields) {
    List fieldNames = new ArrayList();
    Iterator iterator = params.keySet().iterator();
    while (iterator.hasNext()) {
      String fieldName = (String) iterator.next();
      if (null != ignoreFields && ignoreFields.contains(fieldName)) {
        continue;
      }
      fieldNames.add(fieldName);
    }
    return fieldNames;
  }
  public static String toSortedSequence(Map params) {
    List ignoreFields = new ArrayList();
    List fieldNameList = generalFormSequence(params, ignoreFields);
    Collections.sort(fieldNameList);//
    StringBuffer seq = new StringBuffer();
    for (int i = 0; i < fieldNameList.size(); i++) {
        	  
        	 /*
        	  if( i != 0 ){
        		  seq.append("&" );
        	  }
        	  */
      String fieldName = (String) fieldNameList.get(i);
      String value = (String) params.get(fieldName);
      if (value != "") {
        seq.append(fieldName + value);
      }
    }
    return seq.toString();
  }
}