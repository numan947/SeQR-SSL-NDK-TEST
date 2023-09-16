package com.wifiphase2.openssltest;

import android.net.wifi.WifiEnterpriseConfig;
import android.text.TextUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

public class WifiQrCode {
    private String mQrCode;
    public String SSID;
    public int EAP_METHOD;
    public int PHASE2_AUTH;
    public int GRANULARITY;
    public int HASH_CHOICE;
    public String HashList;
    public ArrayList<Integer> cumHashSize;
    public boolean PROFILE_VALID;

    public WifiQrCode(String qrCodeRawString) throws IllegalArgumentException
    {

        if (TextUtils.isEmpty(qrCodeRawString)) {
            throw new IllegalArgumentException("TAG947: Empty QR code --> veriftycertificatemode");
        }
        mQrCode = qrCodeRawString;
        String[]line = qrCodeRawString.split("\\$");

        if(line.length < 6){
            // will be atleast 6 according to the format
            throw new IllegalArgumentException("TAG947: Incorrect number of inforamtion in the QRCode");
        }

        //parse for valid SSID: https://stackoverflow.com/questions/45249961/javascript-validate-ssid-and-wpa-wpa2
        if(line[0].matches("^[^!#;+\\]\\/\"\\t][^+\\]\\/\"\\t]{0,30}[^ !#;+\\]\\/\"\\t]$|^[^ !#;+\\]\\/\"\\t]$")){
            SSID = line[0];
        }
        else{
            throw new IllegalArgumentException("TAG947: SSID pattern mismatch!");
        }


        // parse EAP_METHOD
        if(line[1].matches("^(0|-*[1-9]+[0-9]*)$")){
            EAP_METHOD = Integer.parseInt(line[1]);
            switch(EAP_METHOD){
                case 25://PEAP
                    EAP_METHOD = WifiEnterpriseConfig.Eap.PEAP;
                    break;
                case 21://TTLS
                    EAP_METHOD = WifiEnterpriseConfig.Eap.TTLS;
                    break;
                default:
                    EAP_METHOD = WifiEnterpriseConfig.Eap.NONE; /**Represents empty config */
                    break;
            }
        }
        else{
            throw new IllegalArgumentException("TAG947: EAP method pattern mismatch!");
        }

        // parse PHASE2_AUTH
        if(line[2].matches("^(0|-*[1-9]+[0-9]*)$")){
            PHASE2_AUTH = Integer.parseInt(line[2]);
            switch(PHASE2_AUTH){
                case 29://MSCHAPV2
                    PHASE2_AUTH = WifiEnterpriseConfig.Phase2.MSCHAPV2;
                    break;
                case 1: //PAP
                    PHASE2_AUTH = WifiEnterpriseConfig.Phase2.PAP;
                    break;
                case 6:
                    PHASE2_AUTH = WifiEnterpriseConfig.Phase2.GTC;
                    break;
                default:
                    PHASE2_AUTH = -1; // Not selected any, so don't allow I guess
                    break;
            }
        }
        else{
            throw new IllegalArgumentException("TAG947: Phase2 Auth pattern mismatch!");
        }

        // parse GRANULARITY
        if(line[3].matches("^(0|-*[1-9]+[0-9]*)$")){
            GRANULARITY = Integer.parseInt(line[3]);
        }
        else{
            throw new IllegalArgumentException("TAG947: Granularity pattern mismatch!");
        }


        // parse HASH_CHOICE
        if(line[4].matches("^(0|-*[1-9]+[0-9]*)$")){
            HASH_CHOICE = Integer.parseInt(line[4]);
        }
        else{
            throw new IllegalArgumentException("TAG947: Hash choice pattern mismatch!");
        }

        // parse all base64 encoded strings
        cumHashSize = new ArrayList<Integer>();
        StringBuilder sbl = new StringBuilder();
        // TODO: ADD option for parsing profile valid date string later
        for(int i=5; i< line.length-1; i++){ // parse until the last line, last line contains the expiary date for the profile
            if(line[i].matches("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$")){
                sbl.append(line[i]);
                if(cumHashSize.isEmpty())
                    cumHashSize.add(line[i].length());
                else
                    cumHashSize.add(cumHashSize.get(cumHashSize.size()-1)+line[i].length());
            }
            else{
                throw new IllegalArgumentException("TAG947: Base64Encoded Hash parsing doesn't match");
            }
        }
        HashList = sbl.toString();

        // parse date and check for validity
        try{
            String dateString = line[line.length - 1];
            SimpleDateFormat dateParser = new SimpleDateFormat("yyyy-MM-dd");
            Date profile_date = dateParser.parse(dateString);
            Date current_date = new Date();

            if(MainActivity.DEBUG) {
                System.out.println("TAG947: Profile date: " + dateString);
                System.out.println("TAG947: Profile date: " + profile_date.toString());
                System.out.println("TAG947: Current date: " + current_date.toString());
            }

            PROFILE_VALID = !(current_date.after(profile_date));

        }catch(ParseException e){
            if(MainActivity.DEBUG)
                System.out.println("Tag947: Profile Expiry Date Parsing Failed!!");
            PROFILE_VALID = false;
        }
        if(MainActivity.DEBUG)
            printParsedQrCode();
    }

    public void printParsedQrCode(){

        System.out.println("SSID: "+this.SSID);
        System.out.println("EAP_METHOD: "+ this.EAP_METHOD);
        System.out.println("PHASE2_AUTH: "+this.PHASE2_AUTH);
        System.out.println("GRANULARITY: "+this.GRANULARITY);
        System.out.println("HASHCHOICE: "+this.HASH_CHOICE);
        System.out.println("Hashes: "+HashList);
        for(int i=0; i<cumHashSize.size(); i++)
            System.out.println(cumHashSize.get(i));
        System.out.println("PROFILE_VALID: "+this.PROFILE_VALID);
    }
}
