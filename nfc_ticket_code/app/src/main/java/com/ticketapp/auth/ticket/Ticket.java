package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Dump;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Reader;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You will
 * need to change the keys, design and implement functions to issue and validate tickets. Keep your
 * code readable and write clarifying comments when necessary.
 */
public class Ticket {

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultMasterKey = TicketActivity.outer.getString(R.string.default_master_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();

    /** TODO: Change these according to your design. Diversify the keys. */
    private static byte[] authenticationKey = defaultAuthenticationKey; // 16-byte key
    private static byte[] hmacTicketKey = defaultHMACKey;
    private static byte[] hmacKey = defaultHMACKey; // 16-byte key
    private static byte[] masterKey = defaultMasterKey; // 16-byte key

    public static byte[] data = new byte[192];
    public static byte[] appTagVersion = "ASv1".getBytes();

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private static Boolean isValid = false;
    private static int remainingUses = 0;
    private static int expiryTime = 0;

    private static String infoToShow = "-"; // Use this to show messages

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(masterKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        return infoToShow;
    }

    private static byte[] getAuthenticationKey() {
        return authenticationKey;
    }

    //set the authentication key
    private static void setAuthenticationKey() {
        // read uid
        byte[] uid = new byte[12];
        utils.readPages(0,3, uid, 0);
        byte[] realUid = Arrays.copyOfRange(uid, 0, 10);

        // generate authentication key based on uid and masterKey
        byte[] tempKey = macAlgorithm.generateMac(realUid);
        authenticationKey = Arrays.copyOfRange(tempKey, 0, 16);
    }

    // set the HMAC key
    private static void setHmacTicketKey() throws GeneralSecurityException {
        // read UID
        byte[] uid = new byte[12];
        utils.readPages(0,3, uid, 0);
        byte[] realUid = Arrays.copyOfRange(uid, 0, 10);

        // generate HMAC key based on uid and hmacKey
        TicketMac macHmacTicketKey = new TicketMac();
        macHmacTicketKey.setKey(hmacKey);
        byte[] tempKey = macAlgorithm.generateMac(realUid);

        hmacTicketKey = Arrays.copyOfRange(tempKey, 0, 16);
    }

    private static void setExpiryTime(int time){
        expiryTime = time;
    }


    // generate the HMAC with data (HMAC key is used)
    private static byte[] generateMac (byte[] data) throws GeneralSecurityException {
        TicketMac macAuthenticationKey = new TicketMac();
        macAuthenticationKey.setKey(hmacTicketKey);

        byte[] hmacValue = macAuthenticationKey.generateMac(data);

        // return only first 4 bytes
        byte[] currentMac = Arrays.copyOfRange(hmacValue, 0, 4);
        return currentMac;
    }

    private static int getInt(byte[] arr) {
        ByteBuffer arrBuffer = ByteBuffer.wrap(arr); // big-endian by default
        return arrBuffer.getInt();
    }

    private static short getShort(byte[] arr) {
        ByteBuffer arrBuffer = ByteBuffer.wrap(arr); // big-endian by default
        return arrBuffer.getShort();
    }

    private static short getShortLE(byte[] arr) {
        ByteBuffer arrBuffer = ByteBuffer.wrap(arr).order(ByteOrder.LITTLE_ENDIAN);
        return arrBuffer.getShort();
    }

    // get epoch time in seconds with the needed offset
    private static int getEpochTime(int offset_year, int offset_min) {
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());

        c.add(Calendar.YEAR, offset_year);
        c.add(Calendar.MINUTE, offset_min);

        Date date = c.getTime();

        // get epoch in seconds
        int epoch = (int) (date.getTime()/1000);
        return epoch;
    }

    // concatenate 2, 3 or 4 arrays
    private static byte[] concatenateArray(byte[]... d) {
        int len = d.length>3 ? d[3].length:0;
        int len0 = d.length>2 ? d[2].length:0;
        byte[] macData = new byte[d[0].length + d[1].length + len0 + len];

        System.arraycopy(d[0], 0, macData, 0, d[0].length);
        System.arraycopy(d[1], 0, macData, d[0].length, d[1].length);
        if(d.length>2) {
            System.arraycopy(d[2], 0, macData, d[0].length + d[1].length, d[2].length);
        }
        if(d.length>3) {
            System.arraycopy(d[3], 0, macData, d[0].length+d[1].length+d[2].length, d[3].length);
        }

        return macData;
    }

    // concatenate the data and compute HMAC
    private static byte[] getMac(byte[]... d) throws GeneralSecurityException {
        byte[] macData = concatenateArray(d);
        byte[] mac = generateMac(macData);
        return mac;
    }

    // read the counter on page 41 (first two bytes)
    private static byte[] getCounter(){
        byte[] page41 = new byte[4];
        utils.readPages(41, 1, page41, 0);
        byte[] counter = Arrays.copyOfRange(page41, 0, 2);
        return counter;
    }

    private static byte[] getAppTagVersion(){
        byte[] readAppTagVersion = new byte[4];
        utils.readPages(4, 1, readAppTagVersion, 0);
        return readAppTagVersion;
    }

    private static byte[] getFirstTapMaxRides(){
        byte[] rides = new byte[4];
        utils.readPages(5, 1, rides, 0);
        return rides;
    }

    private static byte[] getCardExpiryTime(){
        byte[] cardExpiryTime = new byte[4];
        utils.readPages(6, 1, cardExpiryTime, 0);
        return cardExpiryTime;
    }

    private static byte[] getIssueMac(){
        byte[] issueMac = new byte[4];
        utils.readPages(7, 1, issueMac, 0);
        return issueMac;
    }

    private static byte[] getRidesValidity(){
        byte[] ridesValidity = new byte[4];
        utils.readPages(8, 1, ridesValidity, 0);
        return ridesValidity;
    }

    private static byte[] getTapMac(){
        byte[] tapMac = new byte[4];
        utils.readPages(9, 1, tapMac, 0);
        return tapMac;
    }

    private static boolean authenticate() throws GeneralSecurityException {
        boolean res;

        setAuthenticationKey();
        setHmacTicketKey();

        res = utils.authenticate(authenticationKey);

        // if authentication failed, try the default key
        if (!res) {
            res = utils.authenticate(defaultAuthenticationKey);
        }
        return res;
    }

    private static boolean isCardValid(){
        // get current time
        int currentTime = getEpochTime(0,0);

        // get card expiry time
        byte[] cardExpiryTime = getCardExpiryTime();
        int intExpiryTime = getInt(cardExpiryTime);
        setExpiryTime(intExpiryTime);

        if(intExpiryTime<currentTime) {
            isValid = false;
            return false;
        }

        isValid = true;
        return true;
    }

    private static boolean isIssueMacValid(byte[] readAppTagVersion, byte[] rides, byte[] cardExpiryTime) throws GeneralSecurityException {
        byte[] issueMac = getIssueMac();

        byte[] currentIssueMac = getMac(readAppTagVersion,rides,cardExpiryTime);
        if (!Arrays.equals(currentIssueMac, issueMac)) {
            return false;
        }
        return true;
    }

    private static boolean areRidesValid(){
        int currentTime = getEpochTime(0, 0);
        byte[] ridesValidity = getRidesValidity();
        int intRidesValidity = getInt(ridesValidity);
        if (intRidesValidity < currentTime) {
            return false;
        }
        return true;
    }

    /**
     * Issue new tickets
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {

        boolean res;
        // boolean value to check if it is the first issue for the card and if the tapMac needs to be updated
        boolean firstIssue = false, updateTapMac = false;

        res = authenticate();
        if (!res){
            Utilities.log("Authentication failed in issue().", true);
            infoToShow = "Authentication failed.";
            return false;
        }

        //read the counter
        byte[] counter = getCounter();
        int shortCounter = getShortLE(counter);

        //read app tag version
        byte[] readAppTagVersion = getAppTagVersion();

        //read rides
        byte[] rides = getFirstTapMaxRides();

        //read card expiry
        byte[] cardExpiryTime = getCardExpiryTime();

        if (Arrays.equals(readAppTagVersion, appTagVersion)){
            //check the card expiry time
            res = isCardValid();
            if (!res){
                Utilities.log("Card has expired.", true);
                Date expiry = new Date(Long.parseLong(String.valueOf(expiryTime))*1000);
                SimpleDateFormat sdf = new SimpleDateFormat("HH:mm dd.MM");
                infoToShow = "Card has expired at "+sdf.format(expiry);
                return false;
            }

            //check issueMac
            res = isIssueMacValid(readAppTagVersion,rides,cardExpiryTime);
            if (!res){
                Utilities.log("Issue Mac is invalid.", true);
                infoToShow = "The rides and/or card expiry values has been altered.";
                return false;
            }

            // check if enough space for 5 more rides
            if (shortCounter > (Math.pow(2, 16)-5)){
                Utilities.log("Counter is full, cannot issue new rides.", true);
                infoToShow = "Counter is full, cannot issue new rides.";
                return false;
            }
        }
        else{
            firstIssue = true;
            //exit if counter not empty but this is first issue
            if (shortCounter>0) {
                Utilities.log("Counter is not empty at the first issue, exit.", true);
                infoToShow = "This card does not belong to our ticketing system.";
                return false;
            }

            //write app-tag version
            utils.writePages(appTagVersion, 0, 4, 1);
        }


        byte[] maxRides = Arrays.copyOfRange(rides, 2, 4);
        short shortMaxRides = getShort(maxRides);

        byte[] firstTapRides =  Arrays.copyOfRange(rides, 0, 2);
        short shortFirstTapRides = getShort(firstTapRides);

        // check is the counter is non-zero
        if (shortCounter>0) {
            //read rides validity
            res = areRidesValid();
            boolean firstTap = false;

            if ((shortMaxRides - shortFirstTapRides)==shortCounter){
                firstTap = true;
            }

            if (!res) {
                // differentiate between <no rides valid> and <new rides issued, but not valid yet> cases
                if (firstTap) {
                    shortMaxRides = (short) (shortMaxRides + 5);
                }else {
                    shortMaxRides = (short) (shortCounter + 5);
                }
                shortFirstTapRides = (short) (shortMaxRides - (short) (shortCounter));
                Utilities.log("Old rides are not valid, issue 5 rides.", false);
            }else{
                shortMaxRides = (short) (shortMaxRides + 5);
                shortFirstTapRides = 0;
                updateTapMac = true;
                Utilities.log("Old rides are valid, issue 5 more rides.", false);
            }

        }else{
            if (firstIssue){
                shortMaxRides = (short)(5);
                Utilities.log("First issue, issue 5 rides.", false);
            }
            else{
                shortMaxRides = (short)(shortMaxRides+5);
                Utilities.log("Add 5 rides to the current rides.", false);
            }
            shortFirstTapRides = (short)(shortMaxRides - (short)(shortCounter));
        }


        //update the first tap and max rides
        firstTapRides = ByteBuffer.allocate(2).putShort(shortFirstTapRides).array();
        maxRides = ByteBuffer.allocate(2).putShort(shortMaxRides).array();
        rides = concatenateArray(firstTapRides,maxRides);
        utils.writePages(rides, 0, 5, 1);

        remainingUses = shortMaxRides - shortCounter;

        //card expiry date as one year from now
        int epoch = getEpochTime(1,0);
        byte[] cardExpiry = ByteBuffer.allocate(4).putInt(epoch).array();
        expiryTime = epoch;
        utils.writePages(cardExpiry, 0, 6, 1);

        // write issueMac
        byte[] macValue = getMac(appTagVersion,rides,cardExpiry);
        utils.writePages(macValue, 0, 7, 1);

        if (updateTapMac){
            //compute and write tapMac
            byte[] ridesValidity = getRidesValidity();
            byte[] tapMac = getMac(readAppTagVersion,rides,cardExpiry,ridesValidity);
            utils.writePages(tapMac, 0, 9, 1);
        }

        final byte[] AUTH0 = new byte[] { (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00};
        final byte[] AUTH1 = new byte[] { (byte)0b00000001, (byte)0x00, (byte)0x00, (byte)0x00};

        utils.writePages(AUTH0, 0, 42, 1);
        utils.writePages(AUTH1, 0, 43, 1);

        // lock auth0 and auth1
        final byte[] lockingBytes =  new byte[] {(byte)0b00000000, (byte)0b01100000, (byte)0b00000000, (byte)0b00000000};
        utils.writePages(lockingBytes,0,40,1);

        // lock AppTagVersion so it cannot be overwritten
        Reader.lockPage(4);

        // write key
        utils.writePages(authenticationKey, 0, 44, 4);

        Utilities.log("New card issued.", false);

        // Set information to show for the user
        Date expiry = new Date(Long.parseLong(String.valueOf(expiryTime))*1000);
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm dd.MM.yyyy");
        infoToShow = "Card issued. You have "+(shortMaxRides-shortCounter)+" rides left. The card expires on "+sdf.format(expiry);

        return true;
    }

    /**
     * Use ticket once
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        // authenticate
        res = authenticate();
        if (!res) {
            Utilities.log("Authentication failed in use().", true);
            infoToShow = "Authentication failed.";
            return false;
        }

        // check app-tag version
        byte[] readAppTagVersion = getAppTagVersion();
        if(!Arrays.equals(readAppTagVersion, appTagVersion)){
            Utilities.log("App Tag Version did not match.", true);
            infoToShow = "The card does not belong to our system.";
            return false;
        }

        //check the card validity
        res = isCardValid();
        if(!res) {
            Utilities.log("Card has expired.", true);
            Date expiry = new Date(Long.parseLong(String.valueOf(expiryTime))*1000);
            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm dd.MM");
            infoToShow = "Card has expired at "+sdf.format(expiry);
            return false;
        }

        //check rides
        byte[] rides = getFirstTapMaxRides();
        byte[] firstTapRides =  Arrays.copyOfRange(rides, 0, 2);
        byte[] maxRides = Arrays.copyOfRange(rides, 2, 4);
        short shortMaxRides = getShort(maxRides);
        short shortFirstTapRides = getShort(firstTapRides);

        byte[] counter = getCounter();
        short shortCounter = getShortLE(counter);

        boolean firstTap = false;

        if(shortCounter >= shortMaxRides) {
            Utilities.log("All rides are used.", true);
            infoToShow = "All rides used, please reissue the rides.";
            return false;
        }

        // check if it is the first tap after issuing
        if ((shortMaxRides - shortFirstTapRides)==shortCounter){
            firstTap = true;
        }

        byte[] cardExpiryTime = getCardExpiryTime();

        if(firstTap) {

            //comparing issueMac
            byte[] issueMac = getIssueMac();
            byte[] currentIssueMac = getMac(readAppTagVersion,rides,cardExpiryTime);
            if (!Arrays.equals(currentIssueMac, issueMac)) {
                Utilities.log("IssueMac is not valid", true);
                infoToShow = "The rides and/or card expiry values has been altered";
                return false;
            }

            //write rides validity
            int ridesValidity = getEpochTime(0,1);
            byte[] validityExpiry = ByteBuffer.allocate(4).putInt(ridesValidity).array();
            utils.writePages(validityExpiry, 0, 8, 1);

            //compute and write tapMac
            byte[] tapMac = getMac(readAppTagVersion,rides,cardExpiryTime,validityExpiry);
            utils.writePages(tapMac, 0, 9, 1);
        } else {

            // read rides validity
            res = areRidesValid();
            if(!res) {
                Utilities.log("Rides are not valid", true);
                infoToShow = "You have 0 rides left, please, issue more rides.";
                return false;
            }

            //comparing the tapMac
            byte[] ridesValidity = getRidesValidity();
            byte[] tapMac = getTapMac();
            byte[] currentTapMac = getMac(readAppTagVersion,rides,cardExpiryTime,ridesValidity);
            if (!Arrays.equals(currentTapMac, tapMac)) {
                Utilities.log("TapMac is not valid", true);
                infoToShow = "The rides and/or card expiry and/or card validity values has been altered";
                return false;
            }
        }

        // increase the counter
        shortCounter++;
        byte[] updatedCounter = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(1).array();
        utils.writePages(updatedCounter,0,41,1);

        remainingUses = shortMaxRides - shortCounter;

        // Set information to show for the user
        int ridesValidity = getInt(getRidesValidity());
        Date expiry = new Date(Long.parseLong(String.valueOf(ridesValidity))*1000);
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm dd.MM.yyyy");
        infoToShow = "Card validated. You have "+(shortMaxRides-shortCounter)+" rides left. The rides expire on "+sdf.format(expiry);

        Utilities.log("Card validated.", false);

        return true;
    }
}