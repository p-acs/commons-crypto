/**
 * Copyright 2015  Jan Petendi <jan.petendi@p-acs.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.petendi.commons.crypto.model;

import java.util.Map;

public class HybridEncrypted {

    private byte[] encryptedBody = null;
    private Map<String,String> headers = null;
    private Map<String,byte[]> recipients = null;
    private Map<String,String> certificates = null;
    private byte[] signature = null;
    
    public byte[] getEncryptedBody() {
        return encryptedBody;
    }
    public void setEncryptedBody(byte[] encryptedBody) {
        this.encryptedBody = encryptedBody;
    }
    public Map<String, String> getHeaders() {
        return headers;
    }
    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }
    public Map<String, byte[]> getRecipients() {
        return recipients;
    }
    public void setRecipients(Map<String, byte[]> recipients) {
        this.recipients = recipients;
    }

    public Map<String, String> getCertificates() {
        return certificates;
    }

    public void setCertificates(Map<String, String> certificates) {
        this.certificates = certificates;
    }
    
    public byte[] getSignature() {
        return signature;
    }
    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
    
    
}
