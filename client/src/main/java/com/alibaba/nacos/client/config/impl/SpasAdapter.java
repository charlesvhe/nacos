/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.nacos.client.config.impl;

import com.alibaba.nacos.api.common.Constants;
import com.alibaba.nacos.client.identify.Base64;
import com.alibaba.nacos.client.identify.CredentialService;
import com.alibaba.nacos.client.utils.StringUtils;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;

/**
 * 适配spas接口
 *
 * @author Nacos
 */
public class SpasAdapter {
    public static final String HEADER_TIMESTAMP = "Timestamp";
    public static final String HEADER_SPAS_SIGNATURE = "Spas-Signature";
    public static final String GROUP_KEY = "group";
    public static final String TENANT_KEY = "tenant";

    public static List<String> getSignHeaders(String resource, String secretKey) {
        List<String> header = new ArrayList<String>();
        String timeStamp = String.valueOf(System.currentTimeMillis());
        header.add(HEADER_TIMESTAMP);
        header.add(timeStamp);
        if (secretKey != null) {
            header.add(HEADER_SPAS_SIGNATURE);
            String signature = sign(resource, timeStamp, secretKey);
            header.add(signature);
        }
        return header;
    }

    public static String sign(String resource, String timeStamp, String secretKey) {
        if (StringUtils.isBlank(resource)) {
            return signWithhmacSHA1Encrypt(timeStamp, secretKey);
        } else {
            return signWithhmacSHA1Encrypt(resource + "+" + timeStamp, secretKey);
        }
    }

    public static List<String> getSignHeaders(List<String> paramValues, String secretKey) {
        if (null == paramValues) {
            return null;
        }
        String tenant = null;
        String group = null;
        for (Iterator<String> iter = paramValues.iterator(); iter.hasNext(); ) {
            String key = iter.next();
            String value = iter.next();
            if(TENANT_KEY.equals(key)){
                tenant = value;
            }else if(GROUP_KEY.equals(key)){
                group = value;
            }
        }
        return getSignHeaders(getResource(tenant, group), secretKey);
    }

    public static String getResource(String tenant, String group) {
        String resource = "";
        if (StringUtils.isNotEmpty(tenant) && StringUtils.isNotEmpty(group)) {
            resource = tenant + "+" + group;
        } else if (StringUtils.isNotEmpty(group)) {
            resource = group;
        }
        return resource;
    }

    public static String getSk() {
        return CredentialService.getInstance().getCredential().getSecretKey();
    }

    public static String getAk() {
        return CredentialService.getInstance().getCredential().getAccessKey();
    }

    public static String signWithhmacSHA1Encrypt(String encryptText, String encryptKey) {
        try {
            byte[] data = encryptKey.getBytes("UTF-8");
            // 根据给定的字节数组构造一个密钥,第二参数指定一个密钥算法的名称
            SecretKey secretKey = new SecretKeySpec(data, "HmacSHA1");
            // 生成一个指定 Mac 算法 的 Mac 对象
            Mac mac = Mac.getInstance("HmacSHA1");
            // 用给定密钥初始化 Mac 对象
            mac.init(secretKey);
            byte[] text = encryptText.getBytes("UTF-8");
            byte[] textFinal = mac.doFinal(text);
            // 完成 Mac 操作, base64编码，将byte数组转换为字符串
            return new String(Base64.encodeBase64(textFinal), Constants.ENCODE);
        } catch (Exception e) {
            throw new RuntimeException("signWithhmacSHA1Encrypt fail", e);
        }
    }
}
