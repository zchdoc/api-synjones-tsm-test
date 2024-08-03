package com.synjones.tsm.test.until;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.TypeReference;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HTTP;

import java.io.UnsupportedEncodingException;
import java.util.*;
public class HttpTsmUntil {
  public static HttpPost postForm(String url, Map<String, String> params) {
    HttpPost httpost = new HttpPost(url);
    List<NameValuePair> nvps = new ArrayList<NameValuePair>();
    Set<String> keySet = params.keySet();
    for (String key : keySet) {
      nvps.add(new BasicNameValuePair(key, params.get(key)));
    }
    try {
      // log.info("set utf-8 form entity to httppost");
      httpost.setEntity(new UrlEncodedFormEntity(nvps, HTTP.UTF_8));
    }
    catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }
    return httpost;
  }
  public static String formatSeriData(String data) {
    String obj = "", dot = ",";
    String[] jsons = data.split("&");
    for (int i = 0; i < jsons.length; i++) {
      String[] keyVals = jsons[i].split("=");
      if (i == jsons.length - 1) {
        dot = "";
      }
      obj += '"' + keyVals[0] + '"' + ":" + '"' + keyVals[1] + '"' + dot;
    }
    return ('{' + obj + '}');
  }
  public static Map formatSeriDataToMapWithOutSign(String data) {
    Map returnMap = new HashMap();
    String[] jsons = data.split("&");
    for (int i = 0; i < jsons.length; i++) {
      String[] keyVals = jsons[i].split("=");
      if (!"sign".equalsIgnoreCase(keyVals[0])) {
        returnMap.put(keyVals[0], keyVals[1]);
      }
    }
    return returnMap;
  }
  public static Map<String, String> JsontoMap(JSONObject obj) {
    Map<String, String> params = JSONObject.parseObject(obj.toJSONString(), new TypeReference<Map<String, String>>() {});
    return params;
  }
}
