package com.synjones.tsm.test;
import com.alibaba.fastjson.JSONObject;
import com.synjones.tsm.test.crypto.SignUtils;
import com.synjones.tsm.test.crypto.SignUtilsImpl;
import com.synjones.tsm.test.until.HttpTsmUntil;
import com.synjones.tsm.test.until.SequenceUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
public class GetAccessToken {
  public static String getAccessToken(String DES_KEY, String DESede, String APP_KEY, String PRI_KEY, String ALGORITHM, String TSM_URL, String PUB_KEY_SELF) {
    String minstr;
    try {
      SignUtils signUtils = new SignUtilsImpl();
      String encode_signText = "";
      String retrunResultStr = "";
      String method = "synjones.authorize.access_token";
      SimpleDateFormat sf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      String timestamp = sf.format(new Date());
      String format = "json";
      // String app_key = "6E8E42D720232CF53070C32012F1DEBF";
      // String app_key = app;
      StringBuilder access_token = new StringBuilder();
      for (int i = 0; i < 128; i++) {
        access_token.append("0");
      }
      // access_token = access_token;
      String v = "2.0";
      String sign_method = "rsa";
      String request = signUtils.encrypt("{\"authorize_access_token\": {}}", DES_KEY, DESede);
      System.out.println("request==" + request);
      JSONObject jsonParam = new JSONObject();
      jsonParam.put("access_token", access_token.toString());//
      jsonParam.put("app_key", APP_KEY);//
      jsonParam.put("method", method);//
      jsonParam.put("timestamp", timestamp);//
      jsonParam.put("v", v);//
      jsonParam.put("format", format);//
      jsonParam.put("request", request);//
      jsonParam.put("sign_method", sign_method);//
      String sortedSource = SequenceUtils.toSortedSequence(jsonParam);
      System.out.println("sortedSource[" + sortedSource + "]");
      String signText = signUtils.sign(sortedSource, PRI_KEY, ALGORITHM);
      System.out.println("singText:" + signText);
      encode_signText = URLEncoder.encode(URLEncoder.encode(signText, "UTF-8"), "UTF-8");
      HttpClient httpclient = HttpClients.createDefault();
      jsonParam.put("sign", signText);
      System.out.println(jsonParam);
      //JSON转化为Map
      HttpPost httpPost = HttpTsmUntil.postForm(TSM_URL, HttpTsmUntil.JsontoMap(jsonParam));
      HttpResponse response = httpclient.execute(httpPost);
      // HttpEntity entity2 = response.getEntity();
      //System.out.println("result response=="
      //		+ response.getStatusLine().getStatusCode());
      if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
        retrunResultStr = EntityUtils.toString(response.getEntity());
        System.out.println("retrunResultStr=" + retrunResultStr);
        httpPost.abort();
      }
      JSONObject returnJsonObject = JSONObject.parseObject(HttpTsmUntil.formatSeriData(retrunResultStr));
      String errorcode = returnJsonObject.getString("errcode");
      String requestSign = returnJsonObject.getString("sign");
      String sortedRequestSource = SequenceUtils.toSortedSequence(HttpTsmUntil.formatSeriDataToMapWithOutSign(retrunResultStr));
      String decode_signText = URLDecoder.decode(requestSign, "UTF-8");
      String sortedSource_lg = URLDecoder.decode(sortedRequestSource, "UTF-8");
      boolean a = signUtils.verify(sortedSource_lg, decode_signText, PUB_KEY_SELF, ALGORITHM);
      //System.out.println("verify_lg=" + a);
      String requestStr = returnJsonObject.getString("request");
      System.out.println("requestStr=" + requestStr);
      String requestStr1 = URLDecoder.decode(requestStr, "UTF-8");
      minstr = signUtils.decrypt(requestStr1, DES_KEY, DESede);
      System.out.println("getAccesstoken 明文=" + minstr);
      return minstr;
    }
    catch (Exception e) {
      e.printStackTrace();
      return "";
    }
  }
}
